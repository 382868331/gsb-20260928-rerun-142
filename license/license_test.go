package license

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const (
	fictionalDeviceA = "device-TEST-virtual-A"
	fictionalDeviceB = "device-TEST-virtual-B"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

func testLicense(t *testing.T, key *IssuerSecret, device string, nbf, nbt time.Time) *Envelope {
	t.Helper()
	l := License{
		Version:   CurrentFormatVersion,
		LicenseID: "lic-1",
		DeviceID:  device,
		Features:  []string{"print", "scan"},
		IssuedAt:  nbf.Format(time.RFC3339),
		NotBefore: nbf.Format(time.RFC3339),
		NotAfter:  nbt.Format(time.RFC3339),
	}
	env, err := NewSigner(key).Issue(l)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return env
}

func TestRoundTripHappyPath(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, now, now.Add(30*24*time.Hour))
	c := &Checker{Ring: NewKeyRing(key.IssuerPublic), Clock: &fakeClock{now.Add(time.Hour)}}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("expected valid, got err=%v", err)
	}
	if !res.HasFeature("print") || res.HasFeature("admin") {
		t.Fatalf("feature check wrong: %v", res.License.Features)
	}
	if res.Revocation != RevocationUnknown {
		t.Fatalf("missing revocation data must not look checked, got %s", res.Revocation)
	}
}

func TestTamperedContentFails(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, now, now.Add(24*time.Hour))
	c := &Checker{Ring: NewKeyRing(key.IssuerPublic), Clock: &fakeClock{now.Add(time.Hour)}}

	// Tamper with each independently represented claim: features, validity,
	// and device identity.
	tampered := *env
	tampered.License.Features = []string{"print", "scan", "admin"}
	if _, _, err := c.Check(&tampered, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("feature tamper: got %v", err)
	}
	tampered = *env
	tampered.License.NotAfter = now.Add(365 * 24 * time.Hour).Format(time.RFC3339)
	if _, _, err := c.Check(&tampered, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("validity tamper: got %v", err)
	}
	tampered = *env
	tampered.License.DeviceID = fictionalDeviceB
	if _, _, err := c.Check(&tampered, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("device tamper: got %v", err)
	}

	// Tamper with raw bytes of the serialized, imported license.
	data, _ := env.Encode()
	corrupt := append([]byte(nil), data...)
	corrupt[len(corrupt)-10] ^= 0xFF
	if _, _, err := c.CheckBytes(corrupt, fictionalDeviceA, time.Time{}); err == nil {
		t.Fatalf("corrupt serialized license unexpectedly accepted")
	}
}

func TestDeviceIdentityAndValidity(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	nbf := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	nbt := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, nbf, nbt)
	ring := NewKeyRing(key.IssuerPublic)

	// Wrong fictional device.
	c := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(time.Hour)}}
	if _, _, err := c.Check(env, fictionalDeviceB, time.Time{}); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("device mismatch: got %v", err)
	}
	// Before not-before.
	c.Clock = &fakeClock{nbf.Add(-time.Minute)}
	if _, _, err := c.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("not yet valid: got %v", err)
	}
	// Expired.
	c.Clock = &fakeClock{nbt.Add(time.Second)}
	if _, _, err := c.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: got %v", err)
	}
}

func TestClockRollbackCannotExtendValidity(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	nbt := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, nbf, nbt)
	ring := NewKeyRing(key.IssuerPublic)

	// First check happens while the license is valid.
	first := nbt.Add(-48 * time.Hour)
	c := &Checker{Ring: ring, Clock: &fakeClock{first}}
	res, eff, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("first check: %v", err)
	}
	// Real time later runs past expiry; that evaluation fails and advances
	// the anchor past not-after.
	beyond := nbt.Add(24 * time.Hour)
	c.Clock = &fakeClock{beyond}
	res, eff, err = c.Check(env, fictionalDeviceA, eff)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expiry: got %v", err)
	}
	if eff != beyond {
		t.Fatalf("anchor should advance past expiry, got %v", eff)
	}
	// Now the wall clock is rolled back into the validity window. The
	// persisted anchor keeps evaluation at the later time, so the expired
	// license is not resurrected and validity is never extended.
	c.Clock = &fakeClock{nbt.Add(-24 * time.Hour)}
	res, eff2, err := c.Check(env, fictionalDeviceA, eff)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("rollback resurrected expired license: got %v", err)
	}
	if !res.ClockRolledBack {
		t.Fatalf("rollback should be flagged")
	}
	if eff2 != beyond {
		t.Fatalf("effective time must stay at anchor %v, got %v", beyond, eff2)
	}
}

func TestRotationStillValidatesOldLicense(t *testing.T) {
	old, _ := NewIssuerKey("iss", "k1")
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	newKey, _ := NewIssuerKey("iss", "k2")

	// License issued BEFORE rotation with the old key.
	oldEnv := testLicense(t, old, fictionalDeviceA, nbf, nbf.Add(30*24*time.Hour))
	newEnv := testLicense(t, newKey, fictionalDeviceA, nbf, nbf.Add(30*24*time.Hour))

	// Rotation = add the new key while retaining the old key's validity range.
	ring := NewKeyRing(old.IssuerPublic, newKey.IssuerPublic)
	c := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(48 * time.Hour)}}
	if res, _, err := c.Check(oldEnv, fictionalDeviceA, time.Time{}); err != nil || !res.Valid {
		t.Fatalf("old license after rotation: %v", err)
	}
	if res, _, err := c.Check(newEnv, fictionalDeviceA, time.Time{}); err != nil || !res.Valid {
		t.Fatalf("new license: %v", err)
	}

	// An unrecognized (removed/foreign) key is rejected, not silently trusted.
	foreign, _ := NewIssuerKey("iss", "k9")
	foreignEnv := testLicense(t, foreign, fictionalDeviceA, nbf, nbf.Add(30*24*time.Hour))
	if _, _, err := c.Check(foreignEnv, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrUnknownIssuerKey) {
		t.Fatalf("unknown key: got %v", err)
	}
}

func TestRevocationStates(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env := testLicense(t, key, fictionalDeviceA, nbf, nbf.Add(30*24*time.Hour))
	ring := NewKeyRing(key.IssuerPublic)
	now := nbf.Add(time.Hour)

	// Clean, signed list -> checked, valid.
	clean, _ := SignRevocationList(key, RevocationList{GeneratedAt: now.Format(time.RFC3339)})
	c := &Checker{Ring: ring, Clock: &fakeClock{now}, Revocation: clean}
	res, _, err := c.Check(env, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid || res.Revocation != RevocationChecked {
		t.Fatalf("clean list: err=%v state=%s", err, res.Revocation)
	}

	// List containing this license -> revoked.
	rev, _ := SignRevocationList(key, RevocationList{
		GeneratedAt: now.Format(time.RFC3339), RevokedIDs: []string{"lic-1"},
	})
	c.Revocation = rev
	if res, _, err = c.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrRevoked) || res.Revocation != Revoked {
		t.Fatalf("revoked: err=%v state=%s", err, res.Revocation)
	}

	// Tampered revocation list is invalid, never treated as authoritative.
	bad := *rev
	bad.List.RevokedIDs = nil
	c.Revocation = &bad
	if _, _, err := c.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered list: got %v", err)
	}

	// RequireRevocation with missing list -> explicit failure.
	c2 := &Checker{Ring: ring, Clock: &fakeClock{now}, RequireRevocation: true}
	if res, _, err := c2.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrRevocationDataMissing) || res.Revocation != RevocationUnknown {
		t.Fatalf("missing list: err=%v state=%s", err, res.Revocation)
	}
}

func TestMalformedAndVersionChange(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	ring := NewKeyRing(key.IssuerPublic)
	c := &Checker{Ring: ring, Clock: SystemClock}

	if _, _, err := c.CheckBytes([]byte("not json at all"), fictionalDeviceA, time.Time{}); !errors.Is(err, ErrMalformedLicense) {
		t.Fatalf("garbage: %v", err)
	}
	var bare map[string]any
	b, _ := json.Marshal(bare)
	if _, _, err := c.CheckBytes(b, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrMalformedLicense) {
		t.Fatalf("empty object: %v", err)
	}

	// Future/changed format version must be rejected, not best-effort parsed.
	future := License{
		Version: CurrentFormatVersion + 1, LicenseID: "x", DeviceID: fictionalDeviceA,
		IssuedAt: "2026-09-29T00:00:00Z", NotBefore: "2026-09-29T00:00:00Z",
		NotAfter: "2027-09-29T00:00:00Z",
	}
	if _, err := NewSigner(key).Issue(future); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("issuing future version: got %v", err)
	}
	// Craft a v2 envelope by hand (signed) to prove verification also rejects it.
	future.KeyID, future.IssuerID = key.KeyID, key.IssuerID
	body, _ := signingBytes(&future)
	sig := signRaw(key, body)
	env := &Envelope{License: future, Signature: sig}
	if _, _, err := c.Check(env, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("v2 verify: got %v", err)
	}
}
