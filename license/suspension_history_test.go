package license

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A cancellation confirmed while the suspension had not started yet stays
// confirmed when later cumulative lists carry it forward, even after the
// original effective time has passed: the decision instant is the
// GeneratedAt of the list that first carried the record, not of the list
// that happens to be imported now.
func TestHistoricalCancelSurvivesCumulativeUpdates(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))

	s1 := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20))
	c1 := SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"}

	// Update 1 (generated day 5): S1 is planned, then cancelled before it
	// starts. The recipient confirms this basis.
	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, key, 1, day(5), s1, c1)); err != nil {
		t.Fatal(err)
	}

	// Update 2 is generated at day 25, AFTER S1's original effective
	// window. It carries the historical cancel forward and adds a new
	// suspension S2 plus an end-early E2 truncating it. The historical
	// cancel must not turn the whole update stale.
	s2 := suspendRecord("S2", "lic-1", []string{"print"}, []string{"export"}, day(22), day(30))
	e2 := SuspensionRecord{RecordID: "E2", Kind: EndEarly, TargetRecordID: "S2", EndedAt: rfc(day(26))}
	if err := store.Import(ring, signSuspensions(t, key, 2, day(25), s1, c1, s2, e2)); err != nil {
		t.Fatalf("historical cancel must not reject the cumulative update: %v", err)
	}

	// Update 3 (generated day 40, everything over) still carries the same
	// historical records; nothing about them may be re-judged.
	if err := store.Import(ring, signSuspensions(t, key, 3, day(40), s1, c1, s2, e2)); err != nil {
		t.Fatalf("re-confirmed history must stay importable: %v", err)
	}

	// Save/reopen: the confirmed basis survives a restart.
	store, _ = LoadSuspensionStore(path)
	if got := store.Serial("iss"); got != 3 {
		t.Fatalf("serial after reopen: %d", got)
	}

	// Current usable scope at day 27: S1 cancelled (scan free), S2 ended
	// early at day 26 (print/export free again).
	c := &Checker{Ring: ring, Clock: &fakeClock{day(27)}, SuspensionStore: store}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("license stays valid: %v", err)
	}
	if !res.FeatureAvailable("scan") || !res.OperationAvailable("print", "export") {
		t.Fatalf("cancelled/ended restrictions must not apply: %+v", res.Restrictions)
	}

	// At day 23 (inside S2's effective interval) print/export is blocked,
	// scan is not: cancel and end-early remain distinct records.
	c.Clock = &fakeClock{day(23)}
	res, _, _ = c.Check(env, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("scan") || res.OperationAvailable("print", "export") || !res.OperationAvailable("print", "view") {
		t.Fatalf("day 23 scope wrong: %+v", res.Restrictions)
	}

	// Clock rollback to before S1's original window cannot resurrect it:
	// the cancellation is a confirmed fact, not a live interval.
	c.Clock = &fakeClock{day(5)}
	res, eff, _ := c.Check(env, fictionalDeviceA, day(15))
	if !res.ClockRolledBack || !eff.Equal(day(15)) || !res.FeatureAvailable("scan") {
		t.Fatalf("rollback must not revive a cancelled suspension: %+v eff=%v", res.Restrictions, eff)
	}

	// Usage review against the confirmed basis: the cancelled S1 flags
	// nothing; S2 flags only usages inside [day22, day26].
	items := store.Review([]UsageRecord{
		{LicenseID: "lic-1", Feature: "scan", Operation: "run", Time: day(15)},
		{LicenseID: "lic-1", Feature: "print", Operation: "export", Time: day(24)},
		{LicenseID: "lic-1", Feature: "print", Operation: "export", Time: day(28)},
	})
	if len(items) != 1 || items[0].Fact.RecordID != "S2" || !items[0].Usage.Time.Equal(day(24)) {
		t.Fatalf("review must use the resolved historical facts: %+v", items)
	}
}

// A cancellation that arrives for the FIRST time after the suspension
// already started is still rejected, and the rejection leaves the
// previously confirmed basis untouched.
func TestFirstTimeLateCancelStillRejected(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")

	s1 := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20))
	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, key, 1, day(0), s1)); err != nil {
		t.Fatal(err)
	}

	// Generated at day 15, S1 is live: a brand-new cancel-scheduled is
	// too late and must be refused, naming the offending record.
	late := signSuspensions(t, key, 2, day(15), s1,
		SuspensionRecord{RecordID: "C9", Kind: CancelScheduled, TargetRecordID: "S1"})
	err := store.Import(ring, late)
	if !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("late first-time cancel must be rejected: %v", err)
	}
	if !strings.Contains(err.Error(), "C9") {
		t.Fatalf("rejection must name the refused record: %v", err)
	}

	// The last trusted state is intact: serial, facts and usable scope.
	if got := store.Serial("iss"); got != 1 {
		t.Fatalf("rejected update must not advance the serial: %d", got)
	}
	store, _ = LoadSuspensionStore(path)
	env := testLicense(t, key, fictionalDeviceA, suspensionBase, day(40))
	c := &Checker{Ring: ring, Clock: &fakeClock{day(15)}, SuspensionStore: store}
	res, _, _ := c.Check(env, fictionalDeviceA, time.Time{})
	if res.FeatureAvailable("scan") {
		t.Fatal("rejected cancel must not lift the confirmed suspension")
	}

	// Reusing the NAME of a previously confirmed cancel with different
	// content does not grandfather it either: only identical carried-over
	// records keep their original decision instant.
	s2 := suspendRecord("S2", "lic-1", []string{"print"}, nil, day(10), day(20))
	if err := store.Import(ring, signSuspensions(t, key, 2, day(5), s1, s2,
		SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S2"})); err != nil {
		t.Fatal(err)
	}
	forged := signSuspensions(t, key, 3, day(15), s1, s2,
		SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"})
	if err := store.Import(ring, forged); !errors.Is(err, ErrInvalidSuspensionRecord) {
		t.Fatalf("borrowed record name must not bypass validation: %v", err)
	}
	if got := store.Serial("iss"); got != 2 {
		t.Fatalf("forged update must not advance the serial: %d", got)
	}
}

// An ancestor's historical cancellation and end-early propagate down the
// delegation chain exactly like live suspensions do.
func TestHistoricalCancelPropagatesDownChain(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, suspensionBase)
	ring := NewKeyRing(issuer.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")

	s1 := suspendRecord("S1", "root", []string{"print"}, nil, day(2), day(6))
	e1 := SuspensionRecord{RecordID: "E1", Kind: EndEarly, TargetRecordID: "S1", EndedAt: rfc(day(4))}
	s2 := suspendRecord("S2", "root", []string{"print"}, nil, day(7), day(9))
	c2 := SuspensionRecord{RecordID: "C2", Kind: CancelScheduled, TargetRecordID: "S2"}

	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, issuer, 1, day(3), s1, e1, s2, c2)); err != nil {
		t.Fatal(err)
	}
	// Later cumulative update generated after every interval: history
	// stays valid and keeps narrowing the leaf.
	if err := store.Import(ring, signSuspensions(t, issuer, 2, day(40), s1, e1, s2, c2)); err != nil {
		t.Fatalf("historical records must survive later updates: %v", err)
	}
	store, _ = LoadSuspensionStore(path)

	c := &Checker{Ring: ring, Clock: &fakeClock{day(3)}, SuspensionStore: store}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("chain valid, scope narrowed: %v", err)
	}
	if res.FeatureAvailable("print") {
		t.Fatal("ancestor suspension must reach the leaf inside its interval")
	}
	// Past the end-early truncation the leaf scope is restored; the
	// cancelled S2 never applies.
	c.Clock = &fakeClock{day(5)}
	res, _, _ = c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("print") {
		t.Fatal("end-early truncation must release the leaf scope")
	}
	c.Clock = &fakeClock{day(8)}
	res, _, _ = c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !res.FeatureAvailable("print") {
		t.Fatal("cancelled ancestor suspension must not reach the leaf")
	}
}
