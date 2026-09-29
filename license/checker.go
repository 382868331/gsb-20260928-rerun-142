package license

import (
	"crypto/ed25519"
	"strings"
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
	License         License
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
	// RequireRevocation makes a missing list a hard failure. It is false by
	// default: the caller instead sees RevocationUnknown and must not claim
	// revocation was checked.
	RequireRevocation bool
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

	if l.Version != CurrentFormatVersion {
		res.Err = ErrUnsupportedVersion
		return res, eff, res.Err
	}
	pub, ok := c.Ring.lookup(l.IssuerID, l.KeyID)
	if !ok {
		res.Err = ErrUnknownIssuerKey
		return res, eff, res.Err
	}
	body, err := signingBytes(l)
	if err != nil {
		res.Err = ErrMalformedLicense
		return res, eff, res.Err
	}
	if len(env.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(pub.Key), body, env.Signature) {
		res.Err = ErrInvalidSignature
		return res, eff, res.Err
	}

	if strings.TrimSpace(l.DeviceID) == "" || l.DeviceID != deviceID {
		res.Err = ErrDeviceMismatch
		return res, eff, res.Err
	}

	nbf, err1 := time.Parse(time.RFC3339, l.NotBefore)
	nbt, err2 := time.Parse(time.RFC3339, l.NotAfter)
	iat, err3 := time.Parse(time.RFC3339, l.IssuedAt)
	if err1 != nil || err2 != nil || err3 != nil || nbt.Before(nbf) || iat.After(nbt) {
		res.Err = ErrMalformedLicense
		return res, eff, res.Err
	}
	if eff.Before(nbf) {
		res.Err = ErrNotYetValid
		return res, eff, res.Err
	}
	if eff.After(nbt) {
		res.Err = ErrExpired
		return res, eff, res.Err
	}

	// All cryptographic/binding/time checks passed. Handle revocation with
	// an explicit three-valued outcome rather than assuming safety.
	switch {
	case c.Revocation != nil:
		if err := c.Revocation.Verify(c.Ring); err != nil {
			res.Err = err
			res.Revocation = RevocationUnknown
			return res, eff, res.Err
		}
		if c.Revocation.contains(l.LicenseID) {
			res.Revocation = Revoked
			res.Err = ErrRevoked
			return res, eff, res.Err
		}
		res.Revocation = RevocationChecked
	case c.RequireRevocation:
		res.Revocation = RevocationUnknown
		res.Err = ErrRevocationDataMissing
		return res, eff, res.Err
	default:
		res.Revocation = RevocationUnknown
	}

	res.Valid = true
	return res, eff, nil
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
