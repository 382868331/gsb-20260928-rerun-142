package license

import (
	"path/filepath"
	"testing"
	"time"
)

func restrictedChain(t *testing.T, issuer *IssuerSecret, rootDelegator, childDelegator *DelegationSecret, at time.Time) []*Envelope {
	t.Helper()
	rootLicense := License{
		Version:    CurrentFormatVersion,
		LicenseID:  "root",
		DeviceID:   fictionalDeviceA,
		Features:   []string{"docs"},
		Grants:     []Grant{{Resource: "docs", Actions: []string{"read", "write", "delete"}}},
		Delegators: []DelegationKey{rootDelegator.Public()},
		IssuedAt:   at.Format(time.RFC3339),
		NotBefore:  at.Format(time.RFC3339),
		NotAfter:   at.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	root, err := NewSigner(issuer).Issue(rootLicense)
	if err != nil {
		t.Fatal(err)
	}
	childLicense := License{
		Version:    CurrentFormatVersion,
		LicenseID:  "child",
		DeviceID:   fictionalDeviceA,
		Features:   []string{"docs"},
		Grants:     []Grant{{Resource: "docs", Actions: []string{"read", "write"}}},
		Delegators: []DelegationKey{childDelegator.Public()},
		IssuedAt:   at.Add(time.Hour).Format(time.RFC3339),
		NotBefore:  at.Format(time.RFC3339),
		NotAfter:   at.Add(20 * 24 * time.Hour).Format(time.RFC3339),
	}
	child, err := NewDelegationSigner(rootDelegator, issuer.IssuerID).Issue(childLicense, &root.License)
	if err != nil {
		t.Fatal(err)
	}
	leafLicense := License{
		Version:   CurrentFormatVersion,
		LicenseID: "leaf",
		DeviceID:  fictionalDeviceA,
		Features:  []string{"docs"},
		Grants:    []Grant{{Resource: "docs", Actions: []string{"read", "write"}}},
		IssuedAt:  at.Add(2 * time.Hour).Format(time.RFC3339),
		NotBefore: at.Format(time.RFC3339),
		NotAfter:  at.Add(10 * 24 * time.Hour).Format(time.RFC3339),
	}
	leaf, err := NewDelegationSigner(childDelegator, issuer.IssuerID).Issue(leafLicense, &child.License)
	if err != nil {
		t.Fatal(err)
	}
	return []*Envelope{root, child, leaf}
}

func TestRestrictionsIntersectIntervalsAndInherit(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("root-dk")
	childDk, _ := NewDelegationKey("child-dk")
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	chain := restrictedChain(t, key, rootDk, childDk, start)

	writeSuspend := RestrictionEvent{
		EventID:   "root-write-week",
		Type:      RestrictionSuspend,
		Scope:     RestrictionScope{LicenseID: "root", Resource: "docs", Actions: []string{"write"}},
		NotBefore: start.Add(5 * 24 * time.Hour),
		NotAfter:  start.Add(10 * 24 * time.Hour),
	}
	writeEnd := RestrictionEvent{
		EventID:  "end-root-write-week",
		Type:     RestrictionEnd,
		TargetID: "root-write-week",
		EndedAt:  start.Add(7 * 24 * time.Hour),
		Reason:   "incident resolved",
	}
	readSuspend := RestrictionEvent{
		EventID:   "child-read-window",
		Type:      RestrictionSuspend,
		Scope:     RestrictionScope{LicenseID: "child", Resource: "docs", Actions: []string{"read"}},
		NotBefore: start.Add(8 * 24 * time.Hour),
		NotAfter:  start.Add(12 * 24 * time.Hour),
	}
	signed, err := SignRestrictionUpdate(key, RestrictionUpdate{
		Serial: 1, GeneratedAt: start.Add(6 * 24 * time.Hour),
		Events: []RestrictionEvent{writeSuspend, writeEnd, readSuspend},
	})
	if err != nil {
		t.Fatal(err)
	}

	ring := NewKeyRing(key.IssuerPublic)
	at := func(day int) *Checker {
		return &Checker{Ring: ring, Clock: &fakeClock{start.Add(time.Duration(day) * 24 * time.Hour)}, Restriction: signed}
	}

	res, _, err := at(6).CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("partial suspension must leave license valid: %v", err)
	}
	if res.HasGrant("docs", "write") || !res.HasGrant("docs", "read") {
		t.Fatalf("day 6 grants should be read-only, got %#v", res.AvailableGrants)
	}
	if !res.RestrictionBasis.Known || res.RestrictionBasis.Serial != 1 || len(res.RestrictionBasis.Active) != 1 {
		t.Fatalf("check must identify active facts: %#v", res.RestrictionBasis)
	}

	res, _, err = at(9).CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("crossing intervals must not revoke whole grant: %v", err)
	}
	if res.HasGrant("docs", "read") || !res.HasGrant("docs", "write") {
		t.Fatalf("after early end write must return while read is suspended: %#v", res.AvailableGrants)
	}
	if ids := eventIDs(res.RestrictionBasis.Active); len(ids) != 1 || ids[0] != "child-read-window" {
		t.Fatalf("ended suspension must not remain active: %v", ids)
	}
}

func TestDelegatedGrantsCannotWidenOrRestoreRestrictedPart(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("root-dk")
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	parent := &License{
		Version: CurrentFormatVersion, LicenseID: "root", DeviceID: fictionalDeviceA,
		Grants:   []Grant{{Resource: "docs", Actions: []string{"read", "write"}}},
		IssuedAt: start.Format(time.RFC3339), NotBefore: start.Format(time.RFC3339),
		NotAfter: start.Add(10 * 24 * time.Hour).Format(time.RFC3339),
	}
	widened := License{
		Version: CurrentFormatVersion, LicenseID: "child", DeviceID: fictionalDeviceA,
		Grants:   []Grant{{Resource: "docs", Actions: []string{"read", "delete"}}},
		IssuedAt: start.Format(time.RFC3339), NotBefore: start.Format(time.RFC3339),
		NotAfter: start.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	if _, err := NewDelegationSigner(rootDk, key.IssuerID).Issue(widened, parent); err == nil {
		t.Fatal("child must not add an operation absent from the parent")
	}

	wildcard := widened
	wildcard.Grants = []Grant{{Resource: "docs", Actions: []string{"*"}}}
	if _, err := NewDelegationSigner(rootDk, key.IssuerID).Issue(wildcard, parent); err == nil {
		t.Fatal("child wildcard operations must not broaden named parent operations")
	}
}

func TestCancelBeforeStartDiffersFromEndDuringInterval(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, start, start.Add(30*24*time.Hour))
	env.License.Grants = []Grant{{Resource: "docs", Actions: []string{"read", "write"}}}
	// testLicense already signed, so issue a signed envelope carrying grants.
	env, _ = NewSigner(key).Issue(env.License)

	future := RestrictionEvent{
		EventID: "future-write", Type: RestrictionSuspend,
		Scope:     RestrictionScope{Resource: "docs", Actions: []string{"write"}},
		NotBefore: start.Add(10 * 24 * time.Hour), NotAfter: start.Add(12 * 24 * time.Hour),
	}
	cancel := RestrictionEvent{EventID: "cancel-future", Type: RestrictionCancel, TargetID: future.EventID, CanceledAt: start.Add(2 * 24 * time.Hour)}
	signed, err := SignRestrictionUpdate(key, RestrictionUpdate{Serial: 1, GeneratedAt: start.Add(2 * time.Hour), Events: []RestrictionEvent{future, cancel}})
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{Ring: NewKeyRing(key.IssuerPublic), Clock: &fakeClock{start.Add(11 * 24 * time.Hour)}, Restriction: signed}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.HasGrant("docs", "write") || len(res.RestrictionBasis.Active) != 0 {
		t.Fatalf("canceled future suspension must never become active: %v %#v", err, res.RestrictionBasis.Active)
	}
}

func TestRestrictionStoreOfflineBasisReviewReopenAndRollback(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("root-dk")
	childDk, _ := NewDelegationKey("child-dk")
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	chain := restrictedChain(t, key, rootDk, childDk, start)
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "restrictions.json")
	store, err := LoadRestrictionStore(path)
	if err != nil {
		t.Fatal(err)
	}

	update, err := SignRestrictionUpdate(key, RestrictionUpdate{
		Serial:      2,
		GeneratedAt: start.Add(7 * 24 * time.Hour),
		Events: []RestrictionEvent{{
			EventID: "late-known-write", Type: RestrictionSuspend,
			Scope:     RestrictionScope{LicenseID: "root", Resource: "docs", Actions: []string{"write"}},
			NotBefore: start.Add(5 * 24 * time.Hour), NotAfter: start.Add(10 * 24 * time.Hour),
		}, {
			EventID: "future-read", Type: RestrictionSuspend,
			Scope:     RestrictionScope{LicenseID: "leaf", Resource: "docs", Actions: []string{"read"}},
			NotBefore: start.Add(20 * 24 * time.Hour), NotAfter: start.Add(21 * 24 * time.Hour),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, update); err != nil {
		t.Fatal(err)
	}

	records := []UsageRecord{
		{RecordID: "old-write", LicenseID: "leaf", Resource: "docs", Action: "write", At: start.Add(6 * 24 * time.Hour), BasisSerial: 1},
		{RecordID: "old-read", LicenseID: "leaf", Resource: "docs", Action: "read", At: start.Add(6 * 24 * time.Hour), BasisSerial: 1},
		{RecordID: "before-future", LicenseID: "leaf", Resource: "docs", Action: "read", At: start.Add(19 * 24 * time.Hour), BasisSerial: 1},
	}
	findings := store.ReviewUsage(chain, records)
	if len(findings) != 1 || findings[0].Record.RecordID != "old-write" || findings[0].Restriction.EventID != "late-known-write" || findings[0].NewSerial != 2 {
		t.Fatalf("only the intersecting old-basis use should be reviewed: %#v", findings)
	}

	reopened, err := LoadRestrictionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{Ring: ring, Clock: &fakeClock{start.Add(6 * 24 * time.Hour)}, RestrictionStore: reopened}
	res, eff, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || res.HasGrant("docs", "write") || res.RestrictionBasis.Serial != 2 {
		t.Fatalf("reopened current scope mismatch: %v %#v", err, res.RestrictionBasis)
	}

	c.Clock = &fakeClock{start.Add(21 * time.Hour)}
	rolled, _, err := c.CheckChain(chain, fictionalDeviceA, eff)
	if err != nil || !rolled.ClockRolledBack || rolled.CheckedAt != eff || rolled.RestrictionBasis.Serial != 2 {
		t.Fatalf("rollback must keep same fact basis and effective time: %v %#v", err, rolled)
	}
}

func TestRestrictionStoreIsMonotonicAndImmutable(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "restrictions.json")
	store, _ := LoadRestrictionStore(path)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	event := RestrictionEvent{EventID: "s1", Type: RestrictionSuspend, Scope: RestrictionScope{Resource: "docs", Actions: []string{"write"}}, NotBefore: at.Add(2 * time.Hour), NotAfter: at.Add(4 * time.Hour)}
	u1, _ := SignRestrictionUpdate(key, RestrictionUpdate{Serial: 1, GeneratedAt: at, Events: []RestrictionEvent{event}})
	if err := store.Import(ring, u1); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, u1); err == nil {
		t.Fatal("duplicate serial must be rejected")
	}
	changed := event
	changed.NotAfter = at.Add(5 * time.Hour)
	u2, _ := SignRestrictionUpdate(key, RestrictionUpdate{Serial: 2, GeneratedAt: at.Add(time.Hour), Events: []RestrictionEvent{changed}})
	if err := store.Import(ring, u2); err == nil {
		t.Fatal("changing a confirmed event must be rejected")
	}
	u3, _ := SignRestrictionUpdate(key, RestrictionUpdate{Serial: 3, GeneratedAt: at.Add(2 * time.Hour), Events: nil})
	if err := store.Import(ring, u3); err == nil {
		t.Fatal("dropping a confirmed event must be rejected")
	}
}

func eventIDs(events []RestrictionEvent) []string {
	var ids []string
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
}
