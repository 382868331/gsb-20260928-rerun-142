package license

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func signedList(t *testing.T, key *IssuerSecret, serial int64, ids ...string) *SignedRevocationList {
	t.Helper()
	s, err := SignRevocationList(key, RevocationList{
		Serial:      serial,
		GeneratedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		RevokedIDs:  ids,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRevocationStoreMonotonicAcrossRestart(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "rev-store.json")

	// First "session": serial 1 revokes L1.
	store, err := LoadRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Import(ring, signedList(t, key, 1, "L1")); err != nil {
		t.Fatal(err)
	}

	// Reopen: trust boundary must persist. L1 stays revoked.
	store, err = LoadRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := store.IsRevoked("iss", "L1"); !ok || !r {
		t.Fatalf("revocation did not survive reopen: revoked=%v known=%v", r, ok)
	}
	if r, ok := store.IsRevoked("iss", "L2"); !ok || r {
		t.Fatalf("L2 unknown until listed: revoked=%v known=%v", r, ok)
	}

	// Serial 2 arrives, cumulative (keeps L1, adds L2).
	if err := store.Import(ring, signedList(t, key, 2, "L1", "L2")); err != nil {
		t.Fatal(err)
	}

	// An OLDER update (delayed copy / restored backup) must not roll back.
	if err := store.Import(ring, signedList(t, key, 1, "L1")); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("older serial: got %v", err)
	}
	// Equal serial is stale as well.
	if err := store.Import(ring, signedList(t, key, 2, "L1")); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("equal serial: got %v", err)
	}
	// A newer serial that drops a previously announced id is also a rollback.
	if err := store.Import(ring, signedList(t, key, 3, "L2")); !errors.Is(err, ErrStaleRevocationData) {
		t.Fatalf("dropped id: got %v", err)
	}
	if r, _ := store.IsRevoked("iss", "L1"); !r {
		t.Fatalf("L1 must remain revoked after rejected updates")
	}

	// A list signed by an untrusted key never enters the store.
	foreign, _ := NewIssuerKey("iss", "k9")
	if err := store.Import(ring, signedList(t, foreign, 99, "L1")); !errors.Is(err, ErrUnknownIssuerKey) {
		t.Fatalf("foreign signer: got %v", err)
	}
}

func TestRevocationStoreChecksUsePersistedState(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "rev-store.json")
	store, err := LoadRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, at, at.Add(30*24*time.Hour))

	c := &Checker{Ring: ring, Clock: &fakeClock{at.Add(time.Hour)}, RevocationStore: store}
	// No data yet: not-checked stays distinct from checked-clean.
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid || res.Revocation != RevocationUnknown {
		t.Fatalf("missing data: err=%v state=%s", err, res.Revocation)
	}

	if err := store.Import(ring, signedList(t, key, 1)); err != nil {
		t.Fatal(err)
	}
	res, _, err = c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid || res.Revocation != RevocationChecked {
		t.Fatalf("clean list via store: err=%v state=%s", err, res.Revocation)
	}

	if err := store.Import(ring, signedList(t, key, 2, "lic-1")); err != nil {
		t.Fatal(err)
	}
	res, _, err = c.Check(env, fictionalDeviceA, time.Time{})
	if !errors.Is(err, ErrRevoked) || res.Revocation != Revoked {
		t.Fatalf("revoked via store: err=%v state=%s", err, res.Revocation)
	}

	// Reopen into a fresh checker: the revoked state is still enforced.
	reopened, err := LoadRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c2 := &Checker{Ring: ring, Clock: &fakeClock{at.Add(time.Hour)}, RevocationStore: reopened}
	if _, _, err := c2.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation not enforced after restart: %v", err)
	}
}

func TestRevocationStoreInterruptedUpdateKeepsOldState(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	path := filepath.Join(t.TempDir(), "rev-store.json")
	store, _ := LoadRevocationStore(path)
	if err := store.Import(ring, signedList(t, key, 1, "L1")); err != nil {
		t.Fatal(err)
	}

	// Simulate an interrupted serial-2 update: leave a stray temp file and
	// never rename it. The store must still open with serial-1 state.
	dir, file := filepath.Split(path)
	tmp := filepath.Join(dir, ".revocations-interrupted-"+file)
	if err := writeFileForTest(tmp, []byte("{not finished")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeFileForTest(tmp) })

	reopened, err := LoadRevocationStore(path)
	if err != nil {
		t.Fatalf("interrupted update must not corrupt store: %v", err)
	}
	if got := reopened.Serial("iss"); got != 1 {
		t.Fatalf("serial moved during interruption: %d", got)
	}
	if r, _ := reopened.IsRevoked("iss", "L1"); !r {
		t.Fatalf("known revocation lost during interruption")
	}
}
