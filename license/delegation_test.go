package license

import (
	"errors"
	"testing"
	"time"
)

func issueChain(t *testing.T, issuer, childKey, grandKey *IssuerSecret, rootDk, childDk *DelegationSecret, at time.Time) []*Envelope {
	t.Helper()
	// Root carries the first-level delegator key.
	rootLic := License{
		Version:    CurrentFormatVersion,
		LicenseID:  "root",
		DeviceID:   fictionalDeviceA,
		Features:   []string{"print", "scan", "admin"},
		Delegators: []DelegationKey{rootDk.Public()},
		IssuedAt:   at.Format(time.RFC3339),
		NotBefore:  at.Format(time.RFC3339),
		NotAfter:   at.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	rootEnv, err := NewSigner(issuer).Issue(rootLic)
	if err != nil {
		t.Fatalf("root issue: %v", err)
	}
	// Child is restricted: fewer features, shorter window, same device; it
	// may delegate one more level.
	childLic := License{
		Version:    CurrentFormatVersion,
		LicenseID:  "child",
		DeviceID:   fictionalDeviceA,
		Features:   []string{"print", "scan"},
		Delegators: []DelegationKey{childDk.Public()},
		IssuedAt:   at.Add(time.Hour).Format(time.RFC3339),
		NotBefore:  at.Format(time.RFC3339),
		NotAfter:   at.Add(20 * 24 * time.Hour).Format(time.RFC3339),
	}
	childEnv, err := NewDelegationSigner(rootDk, issuer.IssuerID).Issue(childLic, &rootEnv.License)
	if err != nil {
		t.Fatalf("child issue: %v", err)
	}
	// Grandchild: further restricted to one feature.
	grandLic := License{
		Version:   CurrentFormatVersion,
		LicenseID: "grand",
		DeviceID:  fictionalDeviceA,
		Features:  []string{"print"},
		IssuedAt:  at.Add(2 * time.Hour).Format(time.RFC3339),
		NotBefore: at.Format(time.RFC3339),
		NotAfter:  at.Add(10 * 24 * time.Hour).Format(time.RFC3339),
	}
	grandEnv, err := NewDelegationSigner(childDk, issuer.IssuerID).Issue(grandLic, &childEnv.License)
	if err != nil {
		t.Fatalf("grand issue: %v", err)
	}
	return []*Envelope{rootEnv, childEnv, grandEnv}
}

func TestMultiLevelDelegationHappyPath(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, at)
	ring := NewKeyRing(issuer.IssuerPublic)
	c := &Checker{Ring: ring, Clock: &fakeClock{at.Add(24 * time.Hour)}}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("chain: %v valid=%v", err, res.Valid)
	}
	if !res.HasFeature("print") || res.HasFeature("admin") {
		t.Fatalf("leaf must only carry print, got %v", res.License.Features)
	}
	if res.License.LicenseID != "grand" {
		t.Fatalf("expected grand leaf, got %s", res.License.LicenseID)
	}
}

func TestSublicenseCannotWidenParent(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rootLic := License{
		Version: CurrentFormatVersion, LicenseID: "root", DeviceID: fictionalDeviceA,
		Features:   []string{"print"},
		Delegators: []DelegationKey{rootDk.Public()},
		IssuedAt:   at.Format(time.RFC3339), NotBefore: at.Format(time.RFC3339),
		NotAfter: at.Add(10 * 24 * time.Hour).Format(time.RFC3339),
	}
	rootEnv, _ := NewSigner(issuer).Issue(rootLic)

	// Extra feature must be refused at issuance.
	child := License{
		Version: CurrentFormatVersion, LicenseID: "child", DeviceID: fictionalDeviceA,
		Features: []string{"print", "admin"},
		IssuedAt: at.Format(time.RFC3339), NotBefore: at.Format(time.RFC3339),
		NotAfter: at.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	if _, err := NewDelegationSigner(rootDk, "iss").Issue(child, &rootEnv.License); !errors.Is(err, ErrDelegationWidensScope) {
		t.Fatalf("extra feature: got %v", err)
	}

	// Wider validity window must be refused.
	child.Features = []string{"print"}
	child.NotAfter = at.Add(20 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := NewDelegationSigner(rootDk, "iss").Issue(child, &rootEnv.License); !errors.Is(err, ErrDelegationWidensScope) {
		t.Fatalf("wider window: got %v", err)
	}
	child.NotAfter = at.Add(5 * 24 * time.Hour).Format(time.RFC3339)

	// Different device must be refused.
	child.DeviceID = fictionalDeviceB
	if _, err := NewDelegationSigner(rootDk, "iss").Issue(child, &rootEnv.License); !errors.Is(err, ErrDelegationWidensScope) {
		t.Fatalf("device widen: got %v", err)
	}
	child.DeviceID = fictionalDeviceA

	// A valid child, then a hand-crafted tampered envelope claiming admin,
	// must be rejected by verification even if issuance enforced the rule.
	good, err := NewDelegationSigner(rootDk, "iss").Issue(child, &rootEnv.License)
	if err != nil {
		t.Fatalf("valid child: %v", err)
	}
	tampered := *good
	tampered.License.Features = []string{"print", "admin"}
	ring := NewKeyRing(issuer.IssuerPublic)
	c := &Checker{Ring: ring, Clock: &fakeClock{at.Add(time.Hour)}}
	if _, _, err := c.CheckChain([]*Envelope{rootEnv, &tampered}, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered child signature: got %v", err)
	}

	// A child signed by a delegator key NOT carried by the parent breaks the chain.
	rogue, _ := NewDelegationKey("dk-rogue")
	rogueEnv, err := NewDelegationSigner(rogue, "iss").Issue(child, &rootEnv.License)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CheckChain([]*Envelope{rootEnv, rogueEnv}, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("rogue delegator: got %v", err)
	}
}

func TestParentFailureCascades(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, at)
	ring := NewKeyRing(issuer.IssuerPublic)

	// After the root has expired (but before the child window would have
	// ended, had it been standalone), the leaf must be invalid with the
	// explicit parent rule.
	// After the whole chain has expired, the failure is attributed to the
	// ancestor that governs the leaf rather than reported in isolation.
	c := &Checker{Ring: ring, Clock: &fakeClock{at.Add(35 * 24 * time.Hour)}}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !errors.Is(err, ErrParentInvalid) || !errors.Is(err, ErrExpired) {
		t.Fatalf("root expiry must cascade: %v", err)
	}
	if res.Valid {
		t.Fatalf("leaf must not be valid when root expired")
	}

	// Revoking an ancestor revokes the whole chain.
	rev, _ := SignRevocationList(issuer, RevocationList{
		Serial: 1, GeneratedAt: at.Format(time.RFC3339), RevokedIDs: []string{"child"},
	})
	c = &Checker{Ring: ring, Clock: &fakeClock{at.Add(24 * time.Hour)}, Revocation: rev}
	res, _, err = c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !errors.Is(err, ErrParentInvalid) || !errors.Is(err, ErrRevoked) || res.Revocation != Revoked {
		t.Fatalf("ancestor revoke: err=%v state=%s", err, res.Revocation)
	}
}

func TestChainWithRotationAndRollback(t *testing.T) {
	// Issuer rotates before issuing this chain; the old key stays trusted.
	old, _ := NewIssuerKey("iss", "old")
	newKey, _ := NewIssuerKey("iss", "new")
	ring := NewKeyRing(old.IssuerPublic, newKey.IssuerPublic)
	rootDk, _ := NewDelegationKey("dk")
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rootLic := License{
		Version: CurrentFormatVersion, LicenseID: "root", DeviceID: fictionalDeviceA,
		Features: []string{"print"}, Delegators: []DelegationKey{rootDk.Public()},
		IssuedAt: at.Format(time.RFC3339), NotBefore: at.Format(time.RFC3339),
		NotAfter: at.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	rootEnv, _ := NewSigner(old).Issue(rootLic)
	childLic := License{
		Version: CurrentFormatVersion, LicenseID: "child", DeviceID: fictionalDeviceA,
		Features: []string{"print"},
		IssuedAt: at.Format(time.RFC3339), NotBefore: at.Format(time.RFC3339),
		NotAfter: at.Add(20 * 24 * time.Hour).Format(time.RFC3339),
	}
	childEnv, _ := NewDelegationSigner(rootDk, "iss").Issue(childLic, &rootEnv.License)

	// First check advances the anchor past the root's expiry; then the clock
	// is rolled back into the window. Old key still trusted, but expiry wins.
	beyond := at.Add(31 * 24 * time.Hour)
	c := &Checker{Ring: ring, Clock: &fakeClock{beyond}}
	_, eff, err := c.CheckChain([]*Envelope{rootEnv, childEnv}, fictionalDeviceA, time.Time{})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected root expiry, got %v", err)
	}
	c.Clock = &fakeClock{at.Add(5 * 24 * time.Hour)}
	res, _, err := c.CheckChain([]*Envelope{rootEnv, childEnv}, fictionalDeviceA, eff)
	if !errors.Is(err, ErrParentInvalid) || !errors.Is(err, ErrExpired) {
		t.Fatalf("rollback resurrected chain: %v", err)
	}
	if !res.ClockRolledBack {
		t.Fatalf("rollback must be flagged on the chain result")
	}
}
