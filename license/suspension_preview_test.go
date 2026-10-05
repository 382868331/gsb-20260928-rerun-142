package license

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func findChange(p *SuspensionPreview, licenseID, feature, op string) *PermissionChange {
	for i := range p.PermissionChanges {
		c := &p.PermissionChanges[i]
		if c.LicenseID == licenseID && c.Feature == feature && c.Operation == op {
			return c
		}
	}
	return nil
}

// A preview of an update shows exactly the permission changes the real
// import produces, across a multi-level chain and for partial
// (operation-level) suspensions, without committing anything.
func TestPreviewMatchesAcceptedUpdate(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, suspensionBase)
	ring := NewKeyRing(issuer.IssuerPublic)
	path := filepath.Join(t.TempDir(), "susp-store.json")

	// Confirmed basis: root print/export suspended day2..day8.
	s1 := suspendRecord("S1", "root", []string{"print"}, []string{"export"}, day(2), day(8))
	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, issuer, 1, day(0), s1)); err != nil {
		t.Fatal(err)
	}

	// Incoming update: end S1 early at day4, and suspend child scan/view
	// day3..day9 (operation-level only).
	e1 := SuspensionRecord{RecordID: "E1", Kind: EndEarly, TargetRecordID: "S1", EndedAt: rfc(day(4))}
	s2 := suspendRecord("S2", "child", []string{"scan"}, []string{"view"}, day(3), day(9))
	incoming := signSuspensions(t, issuer, 2, day(5), s1, e1, s2)

	usages := []UsageRecord{
		{LicenseID: "child", Feature: "scan", Operation: "view", Time: day(4), Chain: []string{"root", "child"}},
		{LicenseID: "root", Feature: "print", Operation: "export", Time: day(3)},
		{LicenseID: "root", Feature: "print", Operation: "export", Time: day(6)},
	}
	p := store.Preview(ring, incoming, chain, usages, day(5), day(5))
	if !p.Accepted || p.RejectReason != "" {
		t.Fatalf("preview must be accepted: %+v", p)
	}
	if p.CurrentSerial != 1 || p.IncomingSerial != 2 {
		t.Fatalf("serials: %+v", p)
	}
	// Restored by the end-early record, at every level of the chain.
	for _, lic := range []string{"root", "child", "grand"} {
		c := findChange(p, lic, "print", "export")
		if c == nil || c.Change != ChangeRestored || len(c.Basis) != 1 || c.Basis[0].RecordID != "E1" {
			t.Fatalf("%s print/export must be restored by E1: %+v", lic, c)
		}
	}
	// Newly revoked by the operation-level suspension on the child.
	c := findChange(p, "child", "scan", "view")
	if c == nil || c.Change != ChangeRevoked || len(c.Basis) != 1 || c.Basis[0].RecordID != "S2" {
		t.Fatalf("child scan/view must be revoked by S2: %+v", c)
	}
	// Untouched scopes produce no change entries.
	if findChange(p, "root", "scan", "view") != nil || findChange(p, "child", "scan", "") != nil ||
		findChange(p, "child", "print", "view") != nil {
		t.Fatalf("unaffected scopes must not appear: %+v", p.PermissionChanges)
	}
	// Applicable records: S1, E1 (root) and S2 (child) — all three kinds
	// of basis are inspectable.
	if len(p.Records) != 3 {
		t.Fatalf("records: %+v", p.Records)
	}
	// Historical usage review: only the child scan/view usage at day4 is
	// NEWLY flagged; the day3 root usage was already flagged by the
	// confirmed basis, and the day6 one stops being flagged (that is a
	// current-permission change, not a new review item).
	if len(p.UsageReviewChanges) != 1 ||
		p.UsageReviewChanges[0].Usage.Feature != "scan" ||
		p.UsageReviewChanges[0].Fact.RecordID != "S2" {
		t.Fatalf("usage review changes: %+v", p.UsageReviewChanges)
	}

	// The preview committed nothing: serial, facts and check results are
	// those of the confirmed basis.
	if got := store.Serial("iss"); got != 1 {
		t.Fatalf("preview must not advance the serial: %d", got)
	}
	c0 := &Checker{Ring: ring, Clock: &fakeClock{day(5)}, SuspensionStore: store}
	res, _, err := c0.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || res.OperationAvailable("print", "export") || res.OperationAvailable("scan", "view") {
		t.Fatalf("preview must not change the confirmed scope: %+v err=%v", res, err)
	}

	// Accept the update for real: the resulting permissions match the
	// preview exactly.
	if err := store.Import(ring, incoming); err != nil {
		t.Fatal(err)
	}
	store, _ = LoadSuspensionStore(path) // save/reopen keeps the basis
	res, _, err = c0.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("chain stays valid after update: %v", err)
	}
	if !res.OperationAvailable("print", "export") {
		t.Fatalf("post-import scope must equal the preview: %+v", res)
	}
	resChild, _, err := c0.CheckChain(chain[:2], fictionalDeviceA, time.Time{})
	if err != nil || !resChild.OperationAvailable("print", "export") ||
		resChild.OperationAvailable("scan", "view") || !resChild.OperationAvailable("scan", "delete") {
		t.Fatalf("post-import child scope must equal the preview: %+v err=%v", resChild, err)
	}
	// Usage review after the real import flags exactly the previewed set.
	items := store.Review(usages)
	if len(items) != 2 { // day3 root print/export (S1) + day4 child scan/view (S2)
		t.Fatalf("post-import review: %+v", items)
	}
}

// Invalid updates are rejected with a reason and the confirmed state is
// preserved: bad signature, stale serial, dropped cumulative record and
// first-time late cancel.
func TestPreviewRejectionsKeepState(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	other, _ := NewIssuerKey("iss", "k2")
	ring := NewKeyRing(issuer.IssuerPublic)
	chain := []*Envelope{testLicense(t, issuer, fictionalDeviceA, suspensionBase, day(40))}
	path := filepath.Join(t.TempDir(), "susp-store.json")

	s1 := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(10), day(20))
	store, _ := LoadSuspensionStore(path)
	if err := store.Import(ring, signSuspensions(t, issuer, 1, day(0), s1)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		list *SignedSuspensionList
		want error
	}{
		{"bad signature", signSuspensions(t, other, 2, day(1), s1), ErrUnknownIssuerKey},
		{"stale serial", signSuspensions(t, issuer, 1, day(1), s1), ErrStaleSuspensionData},
		{"dropped record", signSuspensions(t, issuer, 2, day(1),
			suspendRecord("S9", "lic-1", []string{"print"}, nil, day(2), day(3))), ErrStaleSuspensionData},
		{"first-time late cancel", signSuspensions(t, issuer, 2, day(15), s1,
			SuspensionRecord{RecordID: "C9", Kind: CancelScheduled, TargetRecordID: "S1"}), ErrInvalidSuspensionRecord},
	}
	for _, tc := range cases {
		p := store.Preview(ring, tc.list, chain, nil, day(15), day(15))
		if p.Accepted || p.RejectReason == "" {
			t.Fatalf("%s: must be rejected with a reason: %+v", tc.name, p)
		}
		if !strings.Contains(p.RejectReason, tc.want.Error()) &&
			!errors.Is(errors.New(p.RejectReason), tc.want) {
			t.Fatalf("%s: reason must name the cause %v: %q", tc.name, tc.want, p.RejectReason)
		}
		if len(p.PermissionChanges) != 0 || len(p.UsageReviewChanges) != 0 {
			t.Fatalf("%s: rejected preview shows no changes: %+v", tc.name, p)
		}
		if got := store.Serial("iss"); got != 1 {
			t.Fatalf("%s: rejected preview must not advance the serial: %d", tc.name, got)
		}
	}
	// The confirmed basis is intact after every rejected preview.
	store, _ = LoadSuspensionStore(path)
	facts, ok := store.Facts("iss", "lic-1")
	if !ok || len(facts) != 1 || facts[0].RecordID != "S1" {
		t.Fatalf("confirmed facts unchanged: %+v", facts)
	}
}

// A preview never advances the trusted time anchor: with the system clock
// behind the anchor it evaluates at the anchor time and flags
// clock_rolled_back, and a suspension active at the anchor time is shown
// as revoking — rolling the clock back cannot hide it.
func TestPreviewClockRollback(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(issuer.IssuerPublic)
	chain := []*Envelope{testLicense(t, issuer, fictionalDeviceA, suspensionBase, day(40))}
	store, _ := LoadSuspensionStore(filepath.Join(t.TempDir(), "susp-store.json"))

	s1 := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(5), day(10))
	incoming := signSuspensions(t, issuer, 1, day(0), s1)

	// now=day2, anchor=day6: evaluation must happen at day6 (inside the
	// suspension), not at the rolled-back system time.
	p := store.Preview(ring, incoming, chain, nil, day(2), day(6))
	if !p.Accepted || !p.ClockRolledBack || !p.EvaluatedAt.Equal(day(6)) {
		t.Fatalf("rollback-protected evaluation: %+v", p)
	}
	c := findChange(p, "lic-1", "scan", "")
	if c == nil || c.Change != ChangeRevoked {
		t.Fatalf("scan must show as revoked at the anchor time: %+v", p.PermissionChanges)
	}
	// Without the rollback (now after the suspension) nothing is revoked.
	p2 := store.Preview(ring, incoming, chain, nil, day(11), day(6))
	if findChange(p2, "lic-1", "scan", "") != nil {
		t.Fatalf("expired suspension must not show as a current change: %+v", p2.PermissionChanges)
	}
	if got := store.Serial("iss"); got != -1 {
		t.Fatalf("preview must not commit: serial=%d", got)
	}
}

// A saved preview can be re-opened later and still shows the original
// basis records it reasoned over.
func TestSavedPreviewKeepsBasis(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(issuer.IssuerPublic)
	chain := []*Envelope{testLicense(t, issuer, fictionalDeviceA, suspensionBase, day(40))}
	store, _ := LoadSuspensionStore(filepath.Join(t.TempDir(), "susp-store.json"))

	s1 := suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(5), day(10))
	c1 := SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"}
	p := store.Preview(ring, signSuspensions(t, issuer, 1, day(0), s1, c1), chain, nil, day(6), day(6))
	if !p.Accepted || len(p.Records) != 2 {
		t.Fatalf("preview: %+v", p)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "preview.json")
	if err := writeFileForTest(path, data); err != nil {
		t.Fatal(err)
	}
	// Re-open the saved preview much later: the basis is intact.
	var back SuspensionPreview
	raw, err := readFileForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Records) != 2 || back.Records[0].RecordID != "S1" || back.Records[1].Kind != CancelScheduled {
		t.Fatalf("saved preview must keep its basis: %+v", back.Records)
	}
}
