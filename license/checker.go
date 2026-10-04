package license

import (
	"crypto/ed25519"
	"fmt"
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
	// Restrictions are the confirmed restriction facts that were ACTIVE at
	// the evaluation time and applied to this chain. Every check reports
	// exactly which facts it used.
	Restrictions []RestrictionFact
	// SuspendedFeatures are leaf features currently suspended; the rest
	// of the license keeps working (partial suspension, not revocation).
	SuspendedFeatures []string
	EffectiveFeatures []string
	// SuspensionsKnown is false when no signed suspension data for the
	// root issuer was available; the restriction basis is then unknown
	// rather than "no restrictions".
	SuspensionsKnown bool
	Err              error
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

// FeatureAvailable reports whether the feature is granted AND not
// currently suspended by a confirmed restriction fact.
func (r *Result) FeatureAvailable(name string) bool {
	if !r.HasFeature(name) {
		return false
	}
	for _, f := range r.SuspendedFeatures {
		if f == name {
			return false
		}
	}
	return true
}

// OperationAvailable reports whether (feature, operation) is usable:
// the feature must be available and no active restriction fact may cover
// the pair.
func (r *Result) OperationAvailable(feature, operation string) bool {
	if !r.FeatureAvailable(feature) {
		return false
	}
	for _, f := range r.Restrictions {
		if f.covers(feature, operation) {
			return false
		}
	}
	return true
}

// Checker verifies imported licenses against a trusted ring.
type Checker struct {
	Ring  *KeyRing
	Clock Clock
	// RevocationStore holds the newest signed revocation data applied on
	// this device, keyed by issuer. It survives restarts and refuses to
	// roll backwards. Revocation (below) remains for a single directly
	// supplied list and takes precedence when set.
	RevocationStore *RevocationStore
	Revocation      *SignedRevocationList
	// RequireRevocation makes a missing list a hard failure. It is false by
	// default: the caller instead sees RevocationUnknown and must not claim
	// revocation was checked.
	RequireRevocation bool
	// SuspensionStore holds the newest confirmed suspension data per
	// issuer. Suspensions (below) is a single directly supplied list and
	// takes precedence when set.
	SuspensionStore *SuspensionStore
	Suspensions     *SignedSuspensionList
}

// CheckChain verifies a delegation chain ordered root-first, leaf-last.
// Explicit inheritance rules:
//
//   - The root must be signed by a trusted issuer key; every later license
//     must be signed by a delegator key carried in its immediate parent.
//   - Each child must be a strict subset of its parent: same bound device,
//     no extra features, validity window contained by the parent's.
//   - Revocation of ANY license in the chain invalidates the leaf, and a
//     parent that is expired, not yet valid, revoked or otherwise invalid
//     invalidates every sublicense below it (ErrParentInvalid).
//
// The result describes the effective leaf authorization. As with Check,
// missing revocation data is reported as RevocationUnknown rather than as a
// successful check.
func (c *Checker) CheckChain(chain []*Envelope, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	clk := c.Clock
	if clk == nil {
		clk = SystemClock
	}
	now := clk.Now()
	eff := effectiveTime(now, lastAnchor)
	leaf := Result{CheckedAt: eff, ClockRolledBack: now.Before(lastAnchor)}
	if len(chain) == 0 {
		leaf.Err = ErrMalformedLicense
		return &leaf, eff, leaf.Err
	}

	root := chain[0]
	rootRes, _, err := c.verifyBasics(root, deviceID, eff, leaf.ClockRolledBack)
	if err != nil {
		if len(chain) > 1 {
			rootRes.Err = fmt.Errorf("%w (ancestor %q): %w", ErrParentInvalid, rootRes.License.LicenseID, err)
		}
		return rootRes, eff, rootRes.Err
	}
	if rootRes.License.ParentID != "" {
		rootRes.Err = ErrChainBroken
		return rootRes, eff, rootRes.Err
	}

	for depth := 1; depth < len(chain); depth++ {
		env := chain[depth]
		res, _, err := c.verifyBasics(env, deviceID, eff, leaf.ClockRolledBack)
		if err != nil {
			if depth < len(chain)-1 {
				res.Err = fmt.Errorf("%w (ancestor %q): %w", ErrParentInvalid, res.License.LicenseID, err)
			}
			return res, eff, res.Err
		}
		parent := &chain[depth-1].License
		child := &env.License
		// A child stays bound to the chain's root issuer for revocation.
		if child.IssuerID != root.License.IssuerID {
			res.Err = ErrChainBroken
			return res, eff, res.Err
		}
		if err := c.verifyDelegationSignature(parent, env); err != nil {
			res.Err = err
			return res, eff, res.Err
		}
		if err := ValidateDelegation(parent, child); err != nil {
			res.Err = err
			return res, eff, res.Err
		}
	}

	// Revocation covers the whole chain. A revoked ancestor invalidates the
	// leaf even when the leaf itself is not listed. State is "checked" only
	// when signed data is available; otherwise it stays unknown.
	haveData := false
	for _, env := range chain {
		revoked, known, err := c.revocationStatus(root.License.IssuerID, env.License.LicenseID)
		if err != nil {
			leaf.Err = err
			leaf.Revocation = RevocationUnknown
			return &leaf, eff, err
		}
		if known {
			haveData = true
		}
		if revoked {
			leaf.License = chain[len(chain)-1].License
			leaf.Revocation = Revoked
			if env.License.LicenseID != leaf.License.LicenseID {
				leaf.Err = fmt.Errorf("%w (ancestor %q revoked): %w", ErrParentInvalid, env.License.LicenseID, ErrRevoked)
			} else {
				leaf.Err = ErrRevoked
			}
			return &leaf, eff, leaf.Err
		}
	}
	switch {
	case haveData:
		leaf.Revocation = RevocationChecked
	case c.RequireRevocation:
		leaf.Revocation = RevocationUnknown
		leaf.Err = ErrRevocationDataMissing
		return &leaf, eff, leaf.Err
	default:
		leaf.Revocation = RevocationUnknown
	}

	leaf.License = chain[len(chain)-1].License
	c.applySuspensions(chain, &leaf, eff)
	leaf.Valid = true
	return &leaf, eff, nil
}

// applySuspensions resolves the confirmed suspension basis for every
// chain member and computes the leaf's currently usable scope. A
// suspension recorded against ANY ancestor narrows the leaf: descendants
// can only ever restrict further and can never use re-delegation to
// restore scope an ancestor has suspended. Evaluation uses the effective
// (rollback-protected) time, so turning the clock back cannot escape an
// active suspension.
func (c *Checker) applySuspensions(chain []*Envelope, leaf *Result, eff time.Time) {
	issuer := chain[0].License.IssuerID
	known := false
	var facts []RestrictionFact
	for _, env := range chain {
		fs, ok := c.suspensionFacts(issuer, env.License.LicenseID)
		if ok {
			known = true
		}
		for _, f := range fs {
			if f.activeAt(eff) {
				facts = append(facts, f)
			}
		}
	}
	leaf.SuspensionsKnown = known
	leaf.Restrictions = facts
	suspended := map[string]bool{}
	for _, f := range facts {
		for _, feat := range leaf.License.Features {
			if f.covers(feat, "") {
				suspended[feat] = true
			}
		}
	}
	for _, feat := range leaf.License.Features {
		if suspended[feat] {
			leaf.SuspendedFeatures = append(leaf.SuspendedFeatures, feat)
		} else {
			leaf.EffectiveFeatures = append(leaf.EffectiveFeatures, feat)
		}
	}
}

// suspensionFacts resolves the confirmed facts for one license, preferring
// a directly supplied list over the persistent store.
func (c *Checker) suspensionFacts(issuerID, licenseID string) ([]RestrictionFact, bool) {
	if c.Suspensions != nil {
		if err := c.Suspensions.Verify(c.Ring); err != nil {
			return nil, false
		}
		if c.Suspensions.List.IssuerID != issuerID {
			return nil, false
		}
		return resolveFacts(&c.Suspensions.List, licenseID), true
	}
	if c.SuspensionStore != nil {
		return c.SuspensionStore.Facts(issuerID, licenseID)
	}
	return nil, false
}

// verifyDelegationSignature checks the child envelope against a delegator
// key advertised by the parent. Delegator keys are only trusted because the
// signed parent envelope carries them.
func (c *Checker) verifyDelegationSignature(parent *License, env *Envelope) error {
	d, ok := findDelegator(parent, env.License.KeyID)
	if !ok {
		return ErrChainBroken
	}
	body, err := signingBytes(&env.License)
	if err != nil {
		return ErrMalformedLicense
	}
	if len(env.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(d.Key), body, env.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// revocationStatus resolves the status of one license id against the
// directly supplied list if present, otherwise the persistent store.
func (c *Checker) revocationStatus(issuerID, licenseID string) (revoked, known bool, err error) {
	if c.Revocation != nil {
		if verr := c.Revocation.Verify(c.Ring); verr != nil {
			return false, false, verr
		}
		if c.Revocation.List.IssuerID != issuerID {
			return false, false, nil
		}
		return c.Revocation.contains(licenseID), true, nil
	}
	if c.RevocationStore != nil {
		r, ok := c.RevocationStore.IsRevoked(issuerID, licenseID)
		return r, ok, nil
	}
	return false, false, nil
}

// verifyBasics runs signature, binding and time checks for one license and
// returns a populated Result even on failure.
func (c *Checker) verifyBasics(env *Envelope, deviceID string, eff time.Time, rolledBack bool) (*Result, time.Time, error) {
	res := &Result{CheckedAt: eff, ClockRolledBack: rolledBack}
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
	// Root licenses (no parent) verify against the trusted ring.
	if l.ParentID == "" {
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
	return res, eff, nil
}

// Check validates an already parsed envelope for the given device.
// lastAnchor is the persisted last-observed time for the device (zero value
// on first run). The returned effective time should be persisted as the new
// anchor on every evaluation, including failed ones.
func (c *Checker) Check(env *Envelope, deviceID string, lastAnchor time.Time) (*Result, time.Time, error) {
	return c.CheckChain([]*Envelope{env}, deviceID, lastAnchor)
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
