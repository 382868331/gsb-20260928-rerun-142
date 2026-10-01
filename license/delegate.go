package license

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// DelegationSigner signs a sublicense with a temporary delegator key
// advertised by the parent license. Sublicenses are still bound to the
// original issuer for revocation: only the root issuer's signed revocation
// data can revoke them.
type DelegationSigner struct {
	key      *DelegationSecret
	issuerID string
}

// NewDelegationSigner builds a signer for a child license. issuerID is the
// root issuer of the chain; it is copied into the child so revocation data
// keyed by that issuer still applies.
func NewDelegationSigner(key *DelegationSecret, issuerID string) *DelegationSigner {
	return &DelegationSigner{key: key, issuerID: issuerID}
}

// Issue signs a restricted sublicense. The claimed scope must be no broader
// than the parent's: issuance itself enforces the boundary instead of
// trusting callers to remember it.
func (s *DelegationSigner) Issue(child License, parent *License) (*Envelope, error) {
	if child.Version == 0 {
		child.Version = CurrentFormatVersion
	}
	if child.Version != CurrentFormatVersion {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedVersion, child.Version)
	}
	if parent == nil || strings.TrimSpace(parent.LicenseID) == "" {
		return nil, ErrChainBroken
	}
	child.ParentID = parent.LicenseID
	child.IssuerID = s.issuerID
	child.KeyID = s.key.KeyID
	if err := ValidateDelegation(parent, &child); err != nil {
		return nil, err
	}
	body, err := signingBytes(&child)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(s.key.Secret), body)
	return &Envelope{License: child, Signature: sig}, nil
}

// ValidateDelegation enforces the explicit restriction rules:
//
//  1. the child must reference this exact parent and carry no wider device
//     scope (the single bound device must be identical);
//  2. every child feature must be present on the parent; and
//  3. the child's validity window must be contained within the parent's.
func ValidateDelegation(parent, child *License) error {
	if parent == nil || child == nil {
		return ErrChainBroken
	}
	if child.ParentID != parent.LicenseID {
		return ErrChainBroken
	}
	if strings.TrimSpace(child.DeviceID) == "" || child.DeviceID != parent.DeviceID {
		return ErrDelegationWidensScope
	}
	for _, f := range child.Features {
		if !containsID(parent.Features, f) {
			return ErrDelegationWidensScope
		}
	}
	pnbf, err1 := time.Parse(time.RFC3339, parent.NotBefore)
	pnbt, err2 := time.Parse(time.RFC3339, parent.NotAfter)
	cnbf, err3 := time.Parse(time.RFC3339, child.NotBefore)
	cnbt, err4 := time.Parse(time.RFC3339, child.NotAfter)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return ErrMalformedLicense
	}
	if cnbf.Before(pnbf) || cnbt.After(pnbt) || cnbt.Before(cnbf) {
		return ErrDelegationWidensScope
	}
	return nil
}

// findDelegator locates a delegator key advertised by a license.
func findDelegator(l *License, keyID string) (DelegationKey, bool) {
	for _, d := range l.Delegators {
		if d.KeyID == keyID {
			return d, true
		}
	}
	return DelegationKey{}, false
}
