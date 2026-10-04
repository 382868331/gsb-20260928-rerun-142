package license

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var suspensionBase = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func day(n int) time.Time { return suspensionBase.Add(time.Duration(n) * 24 * time.Hour) }

func rfc(t time.Time) string { return t.Format(time.RFC3339) }

func signSuspensions(t *testing.T, key *IssuerSecret, serial int64, gen time.Time, records ...SuspensionRecord) *SignedSuspensionList {
	t.Helper()
	s, err := SignSuspensionList(key, SuspensionList{
		Serial:      serial,
		GeneratedAt: rfc(gen),
		Records:     records,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func suspendRecord(id, licenseID string, features, ops []string, nbf, nbt time.Time) SuspensionRecord {
	return SuspensionRecord{
		RecordID: id, Kind: Suspend, LicenseID: licenseID,
		Features: features, Operations: ops,
		NotBefore: rfc(nbf), NotAfter: rfc(nbt),
	}
}

func TestPartialSuspensionNarrowsScope(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	now := suspensionBase
	env := testLicense(t, key, fictionalDeviceA, now, day(40))

	// Suspend only "scan" (all operations) for days 10..20.
	list := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)))

	// Inside the interval: license stays valid, scan is suspended, print
	// keeps working. The result names the exact fact used.
	c := &Checker{Ring: ring, Clock: &fakeClock{day(15)}, Suspensions: list}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("partial suspension must not invalidate the license: %v", err)
	}
	if res.FeatureAvailable("scan") || !res.FeatureAvailable("print") {
		t.Fatalf("suspended=%v effective=%v", res.SuspendedFeatures, res.EffectiveFeatures)
	}
	if len(res.Restrictions) != 1 || res.Restrictions[0].RecordID != "S1" || res.Restrictions[0].Serial != 1 {
		t.Fatalf("check must report the facts it used: %+v", res.Restrictions)
	}
	if !res.SuspensionsKnown {
		t.Fatal("signed data was supplied, basis must be known")
	}

	// Outside the interval the full scope is usable again.
	c.Clock = &fakeClock{day(25)}
	res, _, err = c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.FeatureAvailable("scan") {
		t.Fatalf("after the interval scan must be usable: %v %v", err, res.SuspendedFeatures)
	}
	if len(res.Restrictions) != 0 {
		t.Fatalf("no active facts expected, got %+v", res.Restrictions)
	}
}

func TestSuspensionCrossingIntervalsAndOperations(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))

	// Two overlapping intervals on different scopes: S1 suspends the whole
	// "scan" feature for days 10..20, S2 suspends only the "export"
	// operation of "print" for days 15..25.
	list := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)),
		suspendRecord("S2", "lic-1", []string{"print"}, []string{"export"}, day(15), day(25)))

	c := &Checker{Ring: ring, Clock: &fakeClock{day(17)}, Suspensions: list}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Restrictions) != 2 {
		t.Fatalf("both crossing facts must be reported: %+v", res.Restrictions)
	}
	if res.FeatureAvailable("scan") {
		t.Fatal("scan fully suspended in the overlap")
	}
	// print itself remains available, but the export operation is not.
	if !res.FeatureAvailable("print") {
		t.Fatal("operation-level suspension must not remove the whole feature")
	}
	if res.OperationAvailable("print", "export") {
		t.Fatal("export operation must be blocked by S2")
	}
	if !res.OperationAvailable("print", "view") {
		t.Fatal("other operations of print stay usable")
	}

	// After S1 ends but inside S2, only the operation block remains.
	c.Clock = &fakeClock{day(22)}
	res, _, _ = c.Check(env, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("scan") || res.OperationAvailable("print", "export") {
		t.Fatalf("day 22: %+v", res.Restrictions)
	}
}

func TestSuspensionPropagatesDownChain(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, suspensionBase)
	ring := NewKeyRing(issuer.IssuerPublic)

	// Suspend "print" on the ROOT. The leaf ("grand") only carries print,
	// so its whole effective scope collapses even though the license chain
	// itself is valid: re-delegation cannot restore a suspended ancestor
	// scope.
	list := signSuspensions(t, issuer, 1, day(0),
		suspendRecord("S1", "root", []string{"print"}, nil, day(2), day(5)))
	c := &Checker{Ring: ring, Clock: &fakeClock{day(3)}, Suspensions: list}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("chain stays valid, scope is narrowed instead: %v", err)
	}
	if res.FeatureAvailable("print") || len(res.EffectiveFeatures) != 0 {
		t.Fatalf("ancestor suspension must reach the leaf: %+v", res.EffectiveFeatures)
	}

	// Outside the interval the leaf scope is intact again.
	c.Clock = &fakeClock{day(6)}
	res, _, _ = c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("print") {
		t.Fatal("suspension interval over, print must be back")
	}
}

func TestCancelScheduledAndEndEarlyAreDistinct(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))

	// cancel-scheduled erases a suspension that has not started yet.
	cancel := SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"}
	list := signSuspensions(t, key, 1, day(5),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)), cancel)
	c := &Checker{Ring: ring, Clock: &fakeClock{day(15)}, Suspensions: list}
	res, _, _ := c.Check(env, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("scan") || len(res.Restrictions) != 0 {
		t.Fatalf("cancelled-before-start suspension must not apply: %+v", res.Restrictions)
	}

	// end-early truncates a live suspension at ended_at.
	end := SuspensionRecord{RecordID: "E1", Kind: EndEarly, TargetRecordID: "S2", EndedAt: rfc(day(12))}
	list = signSuspensions(t, key, 1, day(11),
		suspendRecord("S2", "lic-1", []string{"scan"}, nil, day(10), day(20)), end)
	c.Suspensions = list
	c.Clock = &fakeClock{day(11)}
	res, _, _ = c.Check(env, fictionalDeviceA, time.Time{})
	if res.FeatureAvailable("scan") {
		t.Fatal("before ended_at the suspension is still active")
	}
	if res.Restrictions[0].NotAfter != rfc(day(12)) {
		t.Fatalf("fact must carry the truncated end: %+v", res.Restrictions[0])
	}
	c.Clock = &fakeClock{day(13)}
	res, _, _ = c.Check(env, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("scan") {
		t.Fatal("after ended_at the suspension is over")
	}

	// Mixing the kinds up is rejected, not reinterpreted.
	badCancel := signSuspensions(t, key, 1, day(15),
		suspendRecord("S3", "lic-1", []string{"scan"}, nil, day(10), day(20)),
		SuspensionRecord{RecordID: "C2", Kind: CancelScheduled, TargetRecordID: "S3"})
	store, _ := LoadSuspensionStore(filepath.Join(t.TempDir(), "s.json"))
	if err := store.Import(ring, badCancel); !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("cancel of a started suspension: %v", err)
	}
	badEnd := signSuspensions(t, key, 1, day(5),
		suspendRecord("S4", "lic-1", []string{"scan"}, nil, day(10), day(20)),
		SuspensionRecord{RecordID: "E2", Kind: EndEarly, TargetRecordID: "S4", EndedAt: rfc(day(12))})
	if err := store.Import(ring, badEnd); !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("end of a not-yet-started suspension: %v", err)
	}
}

func TestHistoricalCancelKeepsOriginalDecisionTime(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")
	store, _ := LoadSuspensionStore(path)

	scheduled := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20))
	cancel := SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"}

	if err := store.Import(ring, signSuspensions(t, key, 1, day(5), scheduled)); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, signSuspensions(t, key, 2, day(8), scheduled, cancel)); err != nil {
		t.Fatalf("cancellation confirmed before start must be accepted: %v", err)
	}

	// A different cancellation first presented after the target started is
	// still late. Its signed record id cannot be borrowed from the old fact.
	lateCancel := SuspensionRecord{RecordID: "C2", Kind: CancelScheduled, TargetRecordID: "S1"}
	if err := store.Import(ring, signSuspensions(t, key, 3, day(15), scheduled, cancel, lateCancel)); !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("late first cancellation must be rejected: %v", err)
	} else if !strings.Contains(err.Error(), "C2") || !strings.Contains(err.Error(), "S1") {
		t.Fatalf("rejection must name the cancel fact and target: %v", err)
	}
	if store.Serial("iss") != 2 {
		t.Fatalf("rejected update must retain serial 2, got %d", store.Serial("iss"))
	}

	// Re-serializing the already confirmed cancellation into a list generated
	// after the suspension would have started must not invalidate that fact.
	if err := store.Import(ring, signSuspensions(t, key, 4, day(15), scheduled, cancel)); err != nil {
		t.Fatalf("historical cancellation must retain its original decision time: %v", err)
	}

	// Reusing the confirmed cancellation record id with changed content is an
	// attempted rollback, not evidence that the new target was cancelled.
	otherScheduled := suspendRecord("S2", "lic-1", []string{"print"}, nil, day(20), day(25))
	mutatedCancel := cancel
	mutatedCancel.TargetRecordID = "S2"
	if err := store.Import(ring, signSuspensions(t, key, 5, day(22), scheduled, cancel, otherScheduled, mutatedCancel)); !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("mutating confirmed record %q must be rejected: %v", cancel.RecordID, err)
	}

	store, err := LoadSuspensionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Serial("iss") != 4 {
		t.Fatalf("reopen must retain last trusted serial 4, got %d", store.Serial("iss"))
	}
	usages := []UsageRecord{
		{LicenseID: "lic-1", Feature: "scan", Operation: "run", Time: day(15)},
		{LicenseID: "lic-1", Feature: "print", Operation: "run", Time: day(22)},
	}
	if items := store.Review(usages); len(items) != 0 {
		t.Fatalf("cancelled and rejected future facts must not review usage: %+v", items)
	}
}

func TestCumulativeCancelAndEndEarlyPreserveOperationsAcrossReopen(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")
	store, _ := LoadSuspensionStore(path)
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))

	scheduled := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20))
	cancel := SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"}
	live := suspendRecord("S2", "lic-1", []string{"print"}, []string{"export"}, day(16), day(20))
	end := SuspensionRecord{RecordID: "E1", Kind: EndEarly, TargetRecordID: "S2", EndedAt: rfc(day(17))}

	if err := store.Import(ring, signSuspensions(t, key, 1, day(5), scheduled)); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, signSuspensions(t, key, 2, day(8), scheduled, cancel, live)); err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, signSuspensions(t, key, 3, day(18), scheduled, cancel, live, end)); err != nil {
		t.Fatal(err)
	}

	store, _ = LoadSuspensionStore(path)
	checker := &Checker{Ring: ring, Clock: &fakeClock{day(16).Add(12 * time.Hour)}, SuspensionStore: store}
	res, _, err := checker.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("check failed: %v", err)
	}
	if !res.FeatureAvailable("scan") || !res.OperationAvailable("print", "view") || res.OperationAvailable("print", "export") {
		t.Fatalf("wrong active scope: effective=%v suspended=%v restrictions=%+v", res.EffectiveFeatures, res.SuspendedFeatures, res.Restrictions)
	}
	if len(res.Restrictions) != 1 || res.Restrictions[0].RecordID != "S2" || res.Restrictions[0].NotAfter != rfc(day(17)) {
		t.Fatalf("check must use the truncated S2 fact: %+v", res.Restrictions)
	}

	checker.Clock = &fakeClock{day(18)}
	res, _, _ = checker.Check(env, fictionalDeviceA, time.Time{})
	if !res.OperationAvailable("print", "export") || len(res.Restrictions) != 0 {
		t.Fatalf("ended restriction must no longer be active: %+v", res.Restrictions)
	}

	usages := []UsageRecord{
		{LicenseID: "lic-1", Feature: "scan", Operation: "run", Time: day(15)},
		{LicenseID: "lic-1", Feature: "print", Operation: "export", Time: day(16).Add(12 * time.Hour)},
		{LicenseID: "lic-1", Feature: "print", Operation: "export", Time: day(18)},
	}
	items := store.Review(usages)
	if len(items) != 1 || items[0].Usage.Time != day(16).Add(12*time.Hour) || items[0].Fact.RecordID != "S2" {
		t.Fatalf("only usage in the truncated interval is reviewed: %+v", items)
	}
}

func TestUsageReviewIsNotRetroactive(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")
	store, _ := LoadSuspensionStore(path)

	usages := []UsageRecord{
		{LicenseID: "lic-1", Feature: "scan", Operation: "run", Time: day(5)},   // before the restriction
		{LicenseID: "lic-1", Feature: "scan", Operation: "run", Time: day(15)},  // inside
		{LicenseID: "lic-1", Feature: "print", Operation: "run", Time: day(15)}, // other feature
	}

	// Offline, no confirmed basis yet: nothing can be flagged.
	if items := store.Review(usages); len(items) != 0 {
		t.Fatalf("no basis, no review items: %+v", items)
	}

	// The restriction takes effect at day 10, AFTER the first usage.
	if err := store.Import(ring, signSuspensions(t, key, 1, day(8),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)))); err != nil {
		t.Fatal(err)
	}
	items := store.Review(usages)
	if len(items) != 1 || !items[0].Usage.Time.Equal(day(15)) {
		t.Fatalf("only the in-interval usage may be flagged: %+v", items)
	}
	if items[0].Fact.RecordID != "S1" {
		t.Fatalf("review must name the fact used: %+v", items[0].Fact)
	}

	// A later update ends the suspension early at day 12; the day-15 usage
	// is then outside the effective interval and no longer flagged, while
	// the day-5 usage is STILL untouched (no retroactive rewriting).
	if err := store.Import(ring, signSuspensions(t, key, 2, day(11),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)),
		SuspensionRecord{RecordID: "E1", Kind: EndEarly, TargetRecordID: "S1", EndedAt: rfc(day(12))})); err != nil {
		t.Fatal(err)
	}
	if items := store.Review(usages); len(items) != 0 {
		t.Fatalf("after end-early no usage remains in the interval: %+v", items)
	}
}

func TestUsageReviewFollowsChainAncestors(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	store, _ := LoadSuspensionStore(filepath.Join(t.TempDir(), "s.json"))
	// Suspension is recorded against the ROOT; usages logged against the
	// leaf of the delegation chain are still flagged when the chain is
	// recorded with the usage.
	if err := store.Import(ring, signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "root", []string{"print"}, nil, day(10), day(20)))); err != nil {
		t.Fatal(err)
	}
	usages := []UsageRecord{
		{LicenseID: "grand", Feature: "print", Operation: "run", Time: day(15), Chain: []string{"root", "child", "grand"}},
		{LicenseID: "grand", Feature: "print", Operation: "run", Time: day(15)}, // no chain recorded
	}
	items := store.Review(usages)
	if len(items) != 1 || items[0].Usage.Chain == nil {
		t.Fatalf("only the chain-annotated usage matches the ancestor fact: %+v", items)
	}
}

func TestSuspensionStoreMonotonicAndReopen(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))

	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)))); err != nil {
		t.Fatal(err)
	}

	// Reopen: the confirmed basis survives, current usable scope identical.
	store, _ = LoadSuspensionStore(path)
	c := &Checker{Ring: ring, Clock: &fakeClock{day(15)}, SuspensionStore: store}
	res1, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || res1.FeatureAvailable("scan") {
		t.Fatalf("suspension lost across reopen: %v %+v", err, res1.SuspendedFeatures)
	}

	// Stale serial and dropped records are refused.
	if err := store.Import(ring, signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)))); !errors.Is(err, ErrStaleSuspensionData) {
		t.Fatalf("stale serial: %v", err)
	}
	if err := store.Import(ring, signSuspensions(t, key, 2, day(1),
		suspendRecord("S9", "lic-1", []string{"print"}, nil, day(1), day(2)))); !errors.Is(err, ErrStaleSuspensionData) {
		t.Fatalf("dropped record: %v", err)
	}

	// A cumulative update applies; after reopen the usable scope is the
	// same as before closing.
	if err := store.Import(ring, signSuspensions(t, key, 2, day(1),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)),
		suspendRecord("S2", "lic-1", []string{"print"}, nil, day(12), day(18)))); err != nil {
		t.Fatal(err)
	}
	store, _ = LoadSuspensionStore(path)
	c.SuspensionStore = store
	res2, _, _ := c.Check(env, fictionalDeviceA, time.Time{})
	if res2.FeatureAvailable("scan") || res2.FeatureAvailable("print") {
		t.Fatalf("both suspensions must apply after reopen: %+v", res2.SuspendedFeatures)
	}
	if len(res2.Restrictions) != 2 || res2.Restrictions[0].Serial != 2 {
		t.Fatalf("facts must come from the newest confirmed list: %+v", res2.Restrictions)
	}
}

func TestSuspensionSurvivesClockRollback(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))
	list := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20)))

	// The device already observed day 15; the wall clock was turned back
	// to day 5, before the suspension starts. The effective time rule must
	// keep the suspension in force.
	c := &Checker{Ring: ring, Clock: &fakeClock{day(5)}, Suspensions: list}
	res, eff, err := c.Check(env, fictionalDeviceA, day(15))
	if err != nil {
		t.Fatal(err)
	}
	if !res.ClockRolledBack || !eff.Equal(day(15)) {
		t.Fatalf("rollback not detected: rolled=%v eff=%v", res.ClockRolledBack, eff)
	}
	if res.FeatureAvailable("scan") {
		t.Fatal("clock rollback must not escape an active suspension")
	}
}

func TestSuspensionBasisUnknownWithoutData(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))
	c := &Checker{Ring: NewKeyRing(key.IssuerPublic), Clock: &fakeClock{day(15)}}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if res.SuspensionsKnown {
		t.Fatal("without signed data the basis is unknown, not empty")
	}
	if !res.FeatureAvailable("scan") {
		t.Fatal("missing suspension data must not block features")
	}
}
