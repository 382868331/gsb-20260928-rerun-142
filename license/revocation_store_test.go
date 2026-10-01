package license

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRevocationStoreMonotonic(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	store := NewRevocationStore(filepath.Join(t.TempDir(), "rev"))

	// Before any material: missing, not "checked".
	if store.HasData() || store.Snapshot() != nil {
		t.Fatalf("fresh store must report missing data")
	}

	l1, _ := SignRevocationList(key, RevocationList{Serial: 1, RevokedIDs: []string{"a"}})
	if err := store.Apply(ring, l1); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if !store.IsRevoked("a") || store.IsRevoked("b") {
		t.Fatalf("unexpected revoked set: %v", store.Snapshot().List.RevokedIDs)
	}

	// Older material cannot roll state back.
	old, _ := SignRevocationList(key, RevocationList{Serial: 1, RevokedIDs: nil})
	if err := store.Apply(ring, old); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("replay same serial: got %v", err)
	}
	oldZero, _ := SignRevocationList(key, RevocationList{Serial: 0})
	if err := store.Apply(ring, oldZero); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("older serial: got %v", err)
	}
	if !store.IsRevoked("a") {
		t.Fatalf("stale update must not remove known revocation")
	}

	// Newer serial union-merges; revoked ids never disappear.
	l2, _ := SignRevocationList(key, RevocationList{Serial: 2, RevokedIDs: []string{"b"}})
	if err := store.Apply(ring, l2); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	if !store.IsRevoked("a") || !store.IsRevoked("b") {
		t.Fatalf("union expected, got %v", store.Snapshot().List.RevokedIDs)
	}

	// Badly signed or foreign-signed material is rejected outright.
	foreign, _ := NewIssuerKey("iss", "k9")
	lForeign, _ := SignRevocationList(foreign, RevocationList{Serial: 3, RevokedIDs: []string{"z"}})
	if err := store.Apply(ring, lForeign); !errors.Is(err, ErrUnknownIssuerKey) {
		t.Fatalf("foreign signer: got %v", err)
	}
	tampered := *l2
	tampered.List.RevokedIDs = []string{"hax"}
	if err := store.Apply(ring, &tampered); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered list: got %v", err)
	}
}

func TestRevocationStorePersistsAcrossReopen(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "rev")

	l1, _ := SignRevocationList(key, RevocationList{Serial: 3, RevokedIDs: []string{"a", "b"}})
	if err := NewRevocationStore(path).Apply(ring, l1); err != nil {
		t.Fatal(err)
	}

	// Simulate save/close/reopen: a fresh instance at the same path must keep
	// the trust boundary and still reject an older serial.
	reopened := NewRevocationStore(path)
	old, _ := SignRevocationList(key, RevocationList{Serial: 1, RevokedIDs: nil})
	if err := reopened.Apply(ring, old); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("stale after reopen: got %v", err)
	}
	if !reopened.IsRevoked("a") || !reopened.IsRevoked("b") {
		t.Fatalf("revocations lost on reopen: %v", reopened.Snapshot().List.RevokedIDs)
	}

	// Checker integration: missing data stays distinct from checked clean.
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, nbf, nbf.Add(30*24*time.Hour))
	c := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(time.Hour)}, Store: reopened}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid || res.Revocation != RevocationChecked {
		t.Fatalf("store-backed check: err=%v state=%s", err, res.Revocation)
	}

	// Empty path = no data at all -> not-checked-data-missing, never clean.
	c2 := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(time.Hour)}, Store: NewRevocationStore(filepath.Join(t.TempDir(), "absent"))}
	res2, _, _ := c2.Check(env, fictionalDeviceA, time.Time{})
	if res2.Revocation != RevocationUnknown {
		t.Fatalf("missing store data must be unknown, got %s", res2.Revocation)
	}
}

func TestRevocationUpdateAcrossIssuerRotation(t *testing.T) {
	old, _ := NewIssuerKey("iss", "k1")
	newKey, _ := NewIssuerKey("iss", "k2")
	ring := NewKeyRing(old.IssuerPublic, newKey.IssuerPublic)
	store := NewRevocationStore(filepath.Join(t.TempDir(), "rev"))

	l1, _ := SignRevocationList(old, RevocationList{Serial: 1, RevokedIDs: []string{"old-lic"}})
	if err := store.Apply(ring, l1); err != nil {
		t.Fatal(err)
	}
	// After rotation the NEW key advances revocation state; the ring keeps
	// both keys so either is verifiable, but only a higher serial applies.
	l2, _ := SignRevocationList(newKey, RevocationList{Serial: 2, RevokedIDs: []string{"new-lic"}})
	if err := store.Apply(ring, l2); err != nil {
		t.Fatalf("post-rotation update: %v", err)
	}
	if !store.IsRevoked("old-lic") || !store.IsRevoked("new-lic") {
		t.Fatalf("unexpected set: %v", store.Snapshot().List.RevokedIDs)
	}
	// Newer-looking serial signed by an unrelated issuer is still rejected.
	foreign, _ := NewIssuerKey("other-issuer", "k1")
	lForeign, _ := SignRevocationList(foreign, RevocationList{Serial: 3, RevokedIDs: []string{"x"}})
	if err := store.Apply(NewKeyRing(old.IssuerPublic, newKey.IssuerPublic, foreign.IssuerPublic), lForeign); !errors.Is(err, ErrMalformedRevocationList) {
		t.Fatalf("cross-issuer update: got %v", err)
	}
}

func TestInterruptedUpdateKeepsPreviousState(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "rev")
	s := NewRevocationStore(path)
	l1, _ := SignRevocationList(key, RevocationList{Serial: 1, RevokedIDs: []string{"a"}})
	if err := s.Apply(ring, l1); err != nil {
		t.Fatal(err)
	}
	// The committed state lives behind a temp-file + rename, so a crash
	// between would leave only the previous file (or none), never a torn one.
	s2 := NewRevocationStore(path)
	if !s2.IsRevoked("a") || s2.Snapshot().List.Serial != 1 {
		t.Fatalf("state not durably committed: %+v", s2.Snapshot())
	}
}
