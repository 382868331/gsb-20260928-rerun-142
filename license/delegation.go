package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// DelegationPrivate is the temporary, per-delegation key material held by the
// party that may issue a sub-license. It is generated locally and is never
// derived from, or mixed with, any real issuer secret.
type DelegationPrivate struct {
	Public []byte `json:"public"`
	Secret []byte `json:"secret"`
}

// NewDelegationKey generates a fresh temporary Ed25519 delegation keypair.
// The public half is embedded in the (issuer- or parent-signed) license;
// the private half authorizes exactly one delegation level beneath it.
func NewDelegationKey() (*DelegationPrivate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DelegationPrivate{Public: pub, Secret: priv}, nil
}

// LicenseChain is an ordered, verifiable delegation path. Entry 0 is the
// root license signed by an issuer key trusted via the key ring; every later
// entry is signed by the delegation key embedded in the preceding entry.
type LicenseChain struct {
	Envelopes []Envelope `json:"envelopes"`
}

// Encode renders the chain to its stable on-disk/import representation.
func (c *LicenseChain) Encode() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ParseChain decodes an imported delegation chain without verifying it.
func ParseChain(data []byte) (*LicenseChain, error) {
	var c LicenseChain
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, ErrMalformedChain
	}
	if len(c.Envelopes) == 0 {
		return nil, ErrMalformedChain
	}
	for i := range c.Envelopes {
		if len(c.Envelopes[i].Signature) == 0 {
			return nil, ErrMalformedChain
		}
	}
	return &c, nil
}

// Leaf returns the final (deepest) license in the chain, or nil when empty.
func (c *LicenseChain) Leaf() *License {
	if c == nil || len(c.Envelopes) == 0 {
		return nil
	}
	return &c.Envelopes[len(c.Envelopes)-1].License
}

// IssueDelegated signs child as a restricted sub-license of parent using the
// delegator's temporary key. It enforces, at issuance time, that a
// sub-license can never expand the parent grant:
//
//   - parent must carry the matching DelegationKey (delegation permitted);
//   - child features must be a subset of the parent features;
//   - child device must be exactly the parent device;
//   - child validity window must be contained in the parent window;
//   - child's own delegation key (when present) only enables the next level.
func IssueDelegated(parent *License, delegator *DelegationPrivate, child License) (*Envelope, error) {
	if parent == nil || delegator == nil {
		return nil, ErrMalformedLicense
	}
	if len(parent.DelegationKey) != ed25519.PublicKeySize ||
		len(delegator.Secret) != ed25519.PrivateKeySize ||
		!ed25519.PublicKey(parent.DelegationKey).Equal(ed25519.PublicKey(delegator.Public)) {
		return nil, ErrDelegationNotPermitted
	}
	if child.Version == 0 {
		child.Version = CurrentFormatVersion
	}
	if child.Version != CurrentFormatVersion {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedVersion, child.Version)
	}
	if child.LicenseID == "" || child.LicenseID == parent.LicenseID {
		return nil, ErrMalformedLicense
	}
	if child.DeviceID == "" || child.DeviceID != parent.DeviceID {
		return nil, ErrDelegationExpandsScope
	}
	if !featureSubset(child.Features, parent.Features) {
		return nil, ErrDelegationExpandsScope
	}
	if len(child.DelegationKey) != 0 && len(child.DelegationKey) != ed25519.PublicKeySize {
		return nil, ErrMalformedLicense
	}

	parentNBF, parentNAT, parentIAT, err := parseValidity(parent)
	if err != nil {
		return nil, err
	}
	childNBF, childNAT, childIAT, err := parseValidity(&child)
	if err != nil {
		return nil, err
	}
	// Containment: the child window must lie entirely inside the parent one,
	// and the child cannot pre-date the parent's issuance.
	if childNBF.Before(parentNBF) || childNAT.After(parentNAT) || childIAT.Before(parentIAT) {
		return nil, ErrDelegationExpandsScope
	}

	// A sub-license keeps the issuer identity of the chain but names no
	// issuer key: verification is anchored via the parent delegation key.
	child.IssuerID = parent.IssuerID
	child.KeyID = ""
	body, err := signingBytes(&child)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		License:   child,
		Signature: ed25519.Sign(ed25519.PrivateKey(delegator.Secret), body),
	}, nil
}

// parseValidity parses the three validity timestamps and checks internal
// consistency (not_after >= not_before and issued_at <= not_after).
func parseValidity(l *License) (nbf, nbt, iat time.Time, err error) {
	nbf, e1 := time.Parse(time.RFC3339, l.NotBefore)
	nbt, e2 := time.Parse(time.RFC3339, l.NotAfter)
	iat, e3 := time.Parse(time.RFC3339, l.IssuedAt)
	if e1 != nil || e2 != nil || e3 != nil || nbt.Before(nbf) || iat.After(nbt) {
		return time.Time{}, time.Time{}, time.Time{}, ErrMalformedLicense
	}
	return nbf, nbt, iat, nil
}

func featureSubset(want, allowed []string) bool {
	for _, f := range want {
		if !containsID(allowed, f) {
			return false
		}
	}
	return true
}
