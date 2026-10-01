package license

import (
	"crypto/ed25519"
	"time"
)

// RevocationState is deliberately three-valued: a missing revocation list
// must never be reported as "checked and clean".
type RevocationState int

const (
	RevocationUnknown RevocationState = iota
	RevocationChecked
	Revoked
)

func (s RevocationState) String() string {
	switch s {
	case RevocationChecked:
		return "checked"
	case Revoked:
		return "revoked"
	default:
		return "not-checked-data-missing"
	}
}

// Result is returned by the single Check entry point shared by every
// application consuming the core.
type Result struct {
	License License
	// Chain lists every license on the verified delegation path, root first;
	// for a plain license it contains only that license.
	Chain           []License
	Valid           bool
	CheckedAt       time.Time
	ClockRolledBack bool
	Revocation      RevocationState
	Err             error
}

// HasFeature reports whether the license grants the named feature.
func (r *Result) HasFeature(name string) bool {
	for _, f := range r.License.Features {
		if f == name {
			return true
		}
	}
	return false
}

// Checker verifies imported licenses against a trusted ring.
type Checker struct {
	Ring       *KeyRing
	Clock      Clock
	Revocation *SignedRevocationList
	// Store, when set, supplies the durable monotonic revocation state. An
	// explicitly set Revocation list takes precedence (e.g. ad-hoc checks).
	Store *RevocationStore
	// RequireRevocation makes a missing list a hard failure. It is false by
	// default: the caller instead sees RevocationUnknown and must not claim
	// revocation was checked.
	RequireRevocation bool
}

// effectiveRevocation resolves the list to consult: an explicitly provided
// signed list wins; otherwise the durable store snapshot is used. Snapshot
// contents were signature-verified when applied, so they are trusted locally
// and are not re-signed.
func (c *Checker) effectiveRevocation() (list *SignedRevocationList, preverified bool) {
	if c.Revocation != nil {
		return c.Revocation, false
	}
	if c.Store != nil {
		return c.Store.Snapshot(), true
	}
	return nil, false
}

// Check validates an already parsed envelope for the given device.
// lastAnchor is the persisted last-observed time for the device (zero value
// on first run). The returned effective time is what the caller should
// persist as the new anchor when valid is true.
func (c *Checker) Check(env *Envelope, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	clk := c.Clock
	if clk == nil {
		clk = SystemClock
	}
	now := clk.Now()
	eff := effectiveTime(now, lastAnchor)
	res := &Result{CheckedAt: eff, ClockRolledBack: now.Before(lastAnchor)}
	if env == nil {
		res.Err = ErrMalformedLicense
		return res, eff, res.Err
	}

	l := &env.License
	res.License = *l
	res.Chain = []License{*l}

	if err := verifyIssuerEnvelope(c.Ring, env); err != nil {
		res.Err = err
		return res, eff, res.Err
	}
	if l.DeviceID == "" || l.DeviceID != deviceID {
		res.Err = ErrDeviceMismatch
		return res, eff, res.Err
	}
	nbf, nbt, _, err := parseValidity(l)
	if err != nil {
		res.Err = ErrMalformedLicense
		return res, eff, res.Err
	}
	if err := checkWindow(eff, nbf, nbt); err != nil {
		res.Err = err
		return res, eff, res.Err
	}

	if err := c.checkRevocation(res, []string{l.LicenseID}); err != nil {
		return res, eff, err
	}

	res.Valid = true
	return res, eff, nil
}

// CheckChain validates a multi-level delegation path for the given device.
// Rules, all enforced from the data itself rather than trusted by position:
//
//   - entry 0 must be signed by a ring-trusted issuer key;
//   - entry i>0 must be signed by the delegation key embedded in entry i-1;
//   - every level must bind the same device and be in its validity window;
//   - each child must be a strict scope subset of its parent (features,
//     device, validity); a chain cannot enlarge anything;
//   - revocation of ANY ancestor invalidates the whole chain, root first.
func (c *Checker) CheckChain(chain *LicenseChain, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	clk := c.Clock
	if clk == nil {
		clk = SystemClock
	}
	now := clk.Now()
	eff := effectiveTime(now, lastAnchor)
	res := &Result{CheckedAt: eff, ClockRolledBack: now.Before(lastAnchor)}
	if chain == nil || len(chain.Envelopes) == 0 {
		res.Err = ErrMalformedChain
		return res, eff, res.Err
	}

	ids := make([]string, 0, len(chain.Envelopes))
	seenIDs := map[string]bool{}
	levels := make([]License, 0, len(chain.Envelopes))
	var parent *License
	var parentNBF, parentNAT, parentIAT time.Time

	for i := range chain.Envelopes {
		env := &chain.Envelopes[i]
		l := &env.License

		if l.Version != CurrentFormatVersion {
			res.Err = ErrUnsupportedVersion
			return res, eff, res.Err
		}
		if l.LicenseID == "" || seenIDs[l.LicenseID] {
			res.Err = ErrDuplicateLicenseID
			return res, eff, res.Err
		}
		seenIDs[l.LicenseID] = true
		ids = append(ids, l.LicenseID)

		if i == 0 {
			if err := verifyIssuerEnvelope(c.Ring, env); err != nil {
				res.Err = err
				return res, eff, res.Err
			}
		} else {
			if len(parent.DelegationKey) != ed25519.PublicKeySize {
				res.Err = ErrDelegationNotPermitted
				return res, eff, res.Err
			}
			if l.KeyID != "" || l.IssuerID != parent.IssuerID {
				res.Err = ErrDelegationSignature
				return res, eff, res.Err
			}
			body, err := signingBytes(l)
			if err != nil {
				res.Err = ErrMalformedChain
				return res, eff, res.Err
			}
			if len(env.Signature) != ed25519.SignatureSize ||
				!ed25519.Verify(ed25519.PublicKey(parent.DelegationKey), body, env.Signature) {
				res.Err = ErrDelegationSignature
				return res, eff, res.Err
			}
		}

		// Binding and time apply at every level; failure of an ancestor is a
		// failure of the entire chain.
		if l.DeviceID == "" || l.DeviceID != deviceID {
			res.Err = ErrDeviceMismatch
			return res, eff, res.Err
		}
		nbf, nbt, iat, err := parseValidity(l)
		if err != nil {
			res.Err = ErrMalformedLicense
			return res, eff, res.Err
		}
		if err := checkWindow(eff, nbf, nbt); err != nil {
			res.Err = err
			return res, eff, res.Err
		}

		if parent != nil {
			// The child cannot widen features, move to another device, reach
			// outside the parent window, or pre-date the parent issuance.
			if l.DeviceID != parent.DeviceID ||
				!featureSubset(l.Features, parent.Features) ||
				nbf.Before(parentNBF) || nbt.After(parentNAT) || iat.Before(parentIAT) {
				res.Err = ErrDelegationExpandsScope
				return res, eff, res.Err
			}
		}

		levels = append(levels, *l)
		parent = l
		parentNBF, parentNAT, parentIAT = nbf, nbt, iat
	}

	leaf := chain.Leaf()
	res.License = *leaf
	res.Chain = levels

	if err := c.checkRevocation(res, ids); err != nil {
		return res, eff, err
	}

	res.Valid = true
	return res, eff, nil
}

// CheckChainBytes parses and checks a serialized imported delegation chain.
func (c *Checker) CheckChainBytes(data []byte, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	chain, err := ParseChain(data)
	if err != nil {
		return &Result{CheckedAt: c.nowOrZero(), Err: err}, c.nowOrZero(), err
	}
	return c.CheckChain(chain, deviceID, lastAnchor)
}

// checkRevocation implements the three-valued outcome over the whole path.
// Any revoked id (ancestors checked first) invalidates the license.
func (c *Checker) checkRevocation(res *Result, ids []string) error {
	list, preverified := c.effectiveRevocation()
	switch {
	case list != nil:
		if !preverified {
			if err := list.Verify(c.Ring); err != nil {
				res.Revocation = RevocationUnknown
				res.Err = err
				return err
			}
		}
		for _, id := range ids {
			if list.contains(id) {
				res.Revocation = Revoked
				res.Err = ErrRevoked
				return ErrRevoked
			}
		}
		res.Revocation = RevocationChecked
	case c.RequireRevocation:
		res.Revocation = RevocationUnknown
		res.Err = ErrRevocationDataMissing
		return ErrRevocationDataMissing
	default:
		res.Revocation = RevocationUnknown
	}
	return nil
}

// verifyIssuerEnvelope checks version, ring membership and the issuer
// signature covering the complete license content.
func verifyIssuerEnvelope(kr *KeyRing, env *Envelope) error {
	l := &env.License
	if l.Version != CurrentFormatVersion {
		return ErrUnsupportedVersion
	}
	pub, ok := kr.lookup(l.IssuerID, l.KeyID)
	if !ok {
		return ErrUnknownIssuerKey
	}
	body, err := signingBytes(l)
	if err != nil {
		return ErrMalformedLicense
	}
	if len(env.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(pub.Key), body, env.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func checkWindow(eff, nbf, nbt time.Time) error {
	if eff.Before(nbf) {
		return ErrNotYetValid
	}
	if eff.After(nbt) {
		return ErrExpired
	}
	return nil
}

// CheckBytes parses and checks a serialized imported license in one call.
func (c *Checker) CheckBytes(data []byte, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	env, err := ParseEnvelope(data)
	if err != nil {
		return &Result{CheckedAt: c.nowOrZero(), Err: err}, c.nowOrZero(), err
	}
	return c.Check(env, deviceID, lastAnchor)
}

func (c *Checker) nowOrZero() time.Time {
	if c.Clock != nil {
		return c.Clock.Now()
	}
	return time.Time{}
}
