package license

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func findChange(p *SuspensionPreview, kind PreviewChangeKind, feature, op string) *PermissionChange {
	for i := range p.Changes {
		c := &p.Changes[i]
		if c.Kind == kind && c.Feature == feature && c.Operation == op {
			return c
		}
	}
	return nil
}

func newPreviewStore(t *testing.T, key *IssuerSecret, lists ...*SignedSuspensionList) (*SuspensionStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "susp-store.json")
	store, err := LoadSuspensionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing(key.IssuerPublic)
	for _, l := range lists {
		if err := store.Import(ring, l); err != nil {
			t.Fatal(err)
		}
	}
	return store, path
}

// Multi-level delegation + partial operation suspension: a previewed
// update on the root narrows the leaf's operation set, and the previewed
// post-state matches a real import followed by CheckChain exactly.
func TestPreviewMatchesAcceptedUpdate(t *testing.T) {
	issuer, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(issuer.IssuerPublic)
	rootDk, _ := NewDelegationKey("dk-root")
	childDk, _ := NewDelegationKey("dk-child")
	at := suspensionBase
	chain := issueChain(t, issuer, nil, nil, rootDk, childDk, at)

	store, storePath := newPreviewStore(t, issuer)

	// Candidate: suspend only operation "export" of feature "print" on the
	// ROOT, active now; the leaf must inherit the narrowing.
	cand := signSuspensions(t, issuer, 1, day(0),
		suspendRecord("S1", "root", []string{"print"}, []string{"export"}, day(0), day(10)))

	scope := PreviewScope{
		LicenseID:  "grand",
		Chain:      []string{"root", "child", "grand"},
		Features:   []string{"print"},
		Operations: []string{"export", "view"},
	}
	anchorPath := filepath.Join(t.TempDir(), "anchor.txt")
	anchor := NewFileAnchor(anchorPath)
	if err := anchor.Advance(day(5)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(storePath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	p := store.Preview(ring, cand, day(5), []PreviewScope{scope}, nil)
	if !p.Accepted {
		t.Fatalf("preview must accept a valid update: %s", p.RejectReason)
	}
	// Operation-level revocation visible; feature itself stays usable.
	if findChange(p, ChangeRevoked, "print", "export") == nil {
		t.Fatalf("expected revoked change for print/export: %+v", p.Changes)
	}
	if findChange(p, ChangeRevoked, "print", "view") != nil || findChange(p, ChangeRevoked, "print", "") != nil {
		t.Fatalf("partial op suspension must not widen: %+v", p.Changes)
	}
	if len(p.NewRecords) != 1 || p.NewRecords[0].RecordID != "S1" || p.NewRecords[0].Kind != Suspend {
		t.Fatalf("preview must list the applicable suspend record: %+v", p.NewRecords)
	}

	// Read-only guarantees: store file, serial and anchor untouched.
	after, err := os.ReadFile(storePath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if !slices.Equal(before, after) {
		t.Fatal("preview must not modify the store file")
	}
	if store.Serial("iss") != -1 {
		t.Fatal("preview must not commit the update")
	}
	last, err := anchor.Last()
	if err != nil || !last.Equal(day(5)) {
		t.Fatalf("preview must not advance the trusted time anchor: %v %v", last, err)
	}

	// Accept the update for real: the checked permissions must equal the
	// previewed post-state.
	if err := store.Import(ring, cand); err != nil {
		t.Fatal(err)
	}
	c := &Checker{Ring: ring, Clock: &fakeClock{day(5)}, SuspensionStore: store}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, day(5))
	if err != nil || !res.Valid {
		t.Fatalf("chain stays valid under partial suspension: %v", err)
	}
	if res.OperationAvailable("print", "export") {
		t.Fatal("accepted update must revoke print/export exactly as previewed")
	}
	if !res.OperationAvailable("print", "view") || !res.FeatureAvailable("print") {
		t.Fatal("other operations must remain available, as previewed")
	}
}

// Restore path: an end-early record lifts an active suspension; the
// preview reports a restored permission with the truncating record as its
// basis, and a saved preview still shows the original grounds after the
// update is accepted and the store reopened.
func TestPreviewRestoreAndSavedPreviewBasis(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	s1 := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)))
	store, storePath := newPreviewStore(t, key, s1)

	endRec := SuspensionRecord{
		RecordID: "E1", Kind: EndEarly, TargetRecordID: "S1", EndedAt: rfc(day(5)),
	}
	cand := signSuspensions(t, key, 2, day(6),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)), endRec)

	scope := PreviewScope{LicenseID: "lic-1", Features: []string{"scan"}}
	p := store.Preview(ring, cand, day(10), []PreviewScope{scope}, nil)
	if !p.Accepted {
		t.Fatalf("preview rejected: %s", p.RejectReason)
	}
	rc := findChange(p, ChangeRestored, "scan", "")
	if rc == nil {
		t.Fatalf("expected restored change: %+v", p.Changes)
	}
	if len(rc.Basis) != 1 || rc.Basis[0].RecordID != "S1" || rc.Basis[0].Serial != 1 {
		t.Fatalf("restore basis must name the original fact: %+v", rc.Basis)
	}
	if len(p.NewRecords) != 1 || p.NewRecords[0].Kind != EndEarly {
		t.Fatalf("preview must list the end-early ground: %+v", p.NewRecords)
	}

	// Save the preview, accept the update, reopen everything: the old
	// preview still shows its original basis (serial 1 fact, serial 2
	// candidate).
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, cand); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadSuspensionStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Serial("iss") != 2 {
		t.Fatal("save/reopen must keep the accepted state")
	}
	var saved SuspensionPreview
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.CurrentSerial != 1 || saved.IncomingSerial != 2 || len(saved.Changes) != 1 {
		t.Fatalf("saved preview lost its original basis: %+v", saved)
	}
	if saved.Changes[0].Basis[0].RecordID != "S1" || saved.Changes[0].Basis[0].NotAfter != rfc(day(20)) {
		t.Fatalf("saved preview basis must be inspectable later: %+v", saved.Changes)
	}
}

// Rejections: invalid signature, first-time late cancel, stale serial and
// non-cumulative data are all refused with a reason, and the confirmed
// state survives every refused preview.
func TestPreviewRejectionsKeepState(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	other, _ := NewIssuerKey("iss", "k-other")
	ring := NewKeyRing(key.IssuerPublic)
	s1 := signSuspensions(t, key, 5, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)))
	store, storePath := newPreviewStore(t, key, s1)
	before, _ := os.ReadFile(storePath)

	scope := []PreviewScope{{LicenseID: "lic-1", Features: []string{"scan"}}}

	// 1. Invalid signature (signed by a key outside the ring).
	bad := signSuspensions(t, other, 6, day(1),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)))
	p := store.Preview(ring, bad, day(1), scope, nil)
	if p.Accepted || !errors.Is(p.RejectErr, ErrUnknownIssuerKey) {
		t.Fatalf("bad signature must be rejected: %+v", p)
	}

	// 2. First-time late cancel: the suspension already started when the
	//    cancel record first appears.
	lateCancel := signSuspensions(t, key, 6, day(10),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)),
		SuspensionRecord{RecordID: "C1", Kind: CancelScheduled, TargetRecordID: "S1"})
	p = store.Preview(ring, lateCancel, day(10), scope, nil)
	if p.Accepted || !errors.Is(p.RejectErr, ErrInvalidSuspensionRecord) {
		t.Fatalf("late cancel must be rejected: %+v", p)
	}

	// 3. Stale serial.
	stale := signSuspensions(t, key, 5, day(1),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(0), day(20)))
	p = store.Preview(ring, stale, day(1), scope, nil)
	if p.Accepted || !errors.Is(p.RejectErr, ErrStaleSuspensionData) {
		t.Fatalf("stale data must be rejected: %+v", p)
	}

	// 4. Non-cumulative: drops the confirmed record.
	dropped := signSuspensions(t, key, 6, day(1),
		suspendRecord("S2", "lic-1", []string{"print"}, nil, day(0), day(20)))
	p = store.Preview(ring, dropped, day(1), scope, nil)
	if p.Accepted || !errors.Is(p.RejectErr, ErrStaleSuspensionData) {
		t.Fatalf("non-cumulative data must be rejected: %+v", p)
	}

	// Every refused preview left the trusted state untouched.
	after, _ := os.ReadFile(storePath)
	if !slices.Equal(before, after) || store.Serial("iss") != 5 {
		t.Fatal("rejected previews must preserve the confirmed state")
	}
}

// Clock rollback: the caller evaluates at the rollback-protected effective
// time; the preview shows the still-active restriction and never advances
// the persisted anchor.
func TestPreviewUnderClockRollback(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	store, _ := newPreviewStore(t, key)
	cand := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "lic-1", []string{"scan"}, nil, day(2), day(10)))

	anchorPath := filepath.Join(t.TempDir(), "anchor.txt")
	anchor := NewFileAnchor(anchorPath)
	if err := anchor.Advance(day(8)); err != nil {
		t.Fatal(err)
	}
	// System clock rolled back to day(1); effective time stays day(8).
	rolledBack := day(1)
	last, _ := anchor.Last()
	eff := effectiveTime(rolledBack, last)

	p := store.Preview(ring, cand, eff, []PreviewScope{{LicenseID: "lic-1", Features: []string{"scan"}}}, nil)
	if !p.Accepted {
		t.Fatalf("preview rejected: %s", p.RejectReason)
	}
	if findChange(p, ChangeRevoked, "scan", "") == nil {
		t.Fatalf("rollback must not escape the active suspension: %+v", p.Changes)
	}
	if !p.EvaluatedAt.Equal(day(8)) {
		t.Fatalf("preview must use the rollback-protected time: %v", p.EvaluatedAt)
	}
	last2, _ := anchor.Last()
	if !last2.Equal(day(8)) {
		t.Fatal("preview must not advance the anchor")
	}
}

// Historical usage review changes are reported separately from current
// permission changes, and only for usage inside the effective interval.
func TestPreviewUsageReviewDelta(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	store, _ := newPreviewStore(t, key)
	cand := signSuspensions(t, key, 1, day(0),
		suspendRecord("S1", "root", []string{"print"}, nil, day(2), day(10)))

	usages := []UsageRecord{
		{LicenseID: "grand", Chain: []string{"root", "child", "grand"}, Feature: "print", Operation: "run", Time: day(3)},
		{LicenseID: "grand", Chain: []string{"root", "child", "grand"}, Feature: "print", Operation: "run", Time: day(15)},
	}
	p := store.Preview(ring, cand, day(1), nil, usages)
	if !p.Accepted {
		t.Fatalf("preview rejected: %s", p.RejectReason)
	}
	if p.UsageReview == nil || len(p.UsageReview.NewlyFlagged) != 1 || len(p.UsageReview.Cleared) != 0 {
		t.Fatalf("expected exactly one newly flagged usage: %+v", p.UsageReview)
	}
	if !p.UsageReview.NewlyFlagged[0].Usage.Time.Equal(day(3)) {
		t.Fatal("only usage inside the effective interval may be flagged")
	}
	if len(p.Changes) != 0 {
		t.Fatalf("no scopes given: review delta must stay separate from permission changes: %+v", p.Changes)
	}
}
