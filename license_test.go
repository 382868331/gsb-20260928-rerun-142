package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	t       *testing.T
	dir     string
	old     *IssuerKey
	new     *IssuerKey
	oldPriv ed25519.PrivateKey
	newPriv ed25519.PrivateKey
	kr      *Keyring
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	old, oldPriv, err := GenerateIssuerKey("project-temp-issuer")
	if err != nil {
		t.Fatal(err)
	}
	new, newPriv, err := GenerateIssuerKey("project-temp-issuer")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		t: t, dir: dir,
		old: old, new: new, oldPriv: oldPriv, newPriv: newPriv,
		kr: NewKeyring(old, new),
	}
}

func (f *fixture) token(key *IssuerKey, priv ed25519.PrivateKey, opts IssueOptions) Token {
	f.t.Helper()
	tok, err := NewSigner(key, priv).Issue(opts)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func validOptions(now time.Time) IssueOptions {
	return IssueOptions{
		DeviceID:  "device-fictional-A",
		Claims:    []Claim{{Feature: "export", MinVersion: "1.0", MaxVersion: "2.0"}},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(30 * 24 * time.Hour),
		IssuedAt:  now.Add(-2 * time.Hour),
	}
}

func (f *fixture) checker() *Checker { return NewChecker(f.kr, filepath.Join(f.dir, "state")) }

func freshRevocation(t *testing.T, f *fixture, now time.Time, serials ...string) {
	t.Helper()
	tok, err := SignRevocationList(f.new, f.newPriv, serials, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveRevocationToken(filepath.Join(f.dir, "state", "revocation.json"), tok); err != nil {
		t.Fatal(err)
	}
}

func TestIssueImportAndOfflineCheck(t *testing.T) {
	f := setup(t)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	tok := f.token(f.old, f.oldPriv, validOptions(now))
	c := f.checker()
	serial, err := c.Import(tok)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.LoadImported(serial)
	if err != nil {
		t.Fatal(err)
	}
	freshRevocation(t, f, now)
	res := c.Check(Request{
		Token: stored, DeviceID: "device-fictional-A", Feature: "export",
		AppVersion: "1.5", Now: now, PersistClock: true,
	})
	if !res.Granted() {
		t.Fatalf("expected granted, got %s: %v", res.Status, res.Err)
	}
	if !res.RevocationChecked {
		t.Fatal("expected revocation to be explicitly checked")
	}
}

func TestTamperedLicenseFails(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	tok := f.token(f.old, f.oldPriv, validOptions(now))
	parts := strings.Split(string(tok), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), "export", "adminx", 1))
	tampered := Token(base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1])
	_, err = tampered.parse(f.kr)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected bad signature, got %v", err)
	}

	corrupt := Token(strings.Replace(string(tok), "A", "B", 1))
	_, err = corrupt.parse(f.kr)
	if err == nil {
		t.Fatal("expected corrupted token to fail")
	}
}

func TestFeatureAndVersionAreSeparateGates(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	tok := f.token(f.old, f.oldPriv, validOptions(now))
	freshRevocation(t, f, now)
	c := f.checker()
	for _, tc := range []struct {
		feature, version string
		grant            bool
	}{
		{"export", "1.5", true},
		{"export", "1.0", true},
		{"export", "2.0", false},
		{"export", "0.9", false},
		{"print", "1.5", false},
	} {
		res := c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: tc.feature, AppVersion: tc.version, Now: now})
		if res.Granted() != tc.grant {
			t.Errorf("feature=%s version=%s granted=%v status=%s", tc.feature, tc.version, res.Granted(), res.Status)
		}
	}
}

func TestValidityWindowAndFictionalDevice(t *testing.T) {
	f := setup(t)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	tok := f.token(f.old, f.oldPriv, validOptions(now))
	freshRevocation(t, f, now)
	c := f.checker()
	req := Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5"}
	req.Now = now.Add(-2 * time.Hour)
	if got := c.Check(req).Status; got != StatusNotYetValid {
		t.Fatalf("not-before: %s", got)
	}
	req.Now = now.Add(30 * 24 * time.Hour)
	if got := c.Check(req).Status; got != StatusExpired {
		t.Fatalf("not-after: %s", got)
	}
	req.Now = now
	req.DeviceID = "device-fictional-B"
	if got := c.Check(req).Status; got != StatusDeviceMismatch {
		t.Fatalf("device: %s", got)
	}
}

func TestKeyRotationStillTrustsOldLicenseWithinValidity(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	oldTok := f.token(f.old, f.oldPriv, validOptions(now))
	newOpts := validOptions(now)
	newOpts.DeviceID = "device-fictional-C"
	newTok := f.token(f.new, f.newPriv, newOpts)
	freshRevocation(t, f, now)
	c := f.checker()
	if r := c.Check(Request{Token: oldTok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5", Now: now}); !r.Granted() {
		t.Fatalf("old key license should remain valid: %s %v", r.Status, r.Err)
	}
	if r := c.Check(Request{Token: newTok, DeviceID: "device-fictional-C", Feature: "export", AppVersion: "1.5", Now: now}); !r.Granted() {
		t.Fatalf("new key license should validate: %s %v", r.Status, r.Err)
	}

	unknown := NewKeyring(f.new)
	if _, err := oldTok.parse(unknown); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("removing old key must not silently trust it: %v", err)
	}
}

func TestRevocationSemantics(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	tok := f.token(f.old, f.oldPriv, validOptions(now))
	lic, err := tok.parse(f.kr)
	if err != nil {
		t.Fatal(err)
	}
	c := f.checker()
	res := c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5", Now: now})
	if res.Status != StatusRevocationMissing || res.RevocationChecked {
		t.Fatalf("missing list must not claim checked: %+v", res)
	}

	freshRevocation(t, f, now)
	if got := c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5", Now: now}).Status; got != StatusGranted {
		t.Fatalf("clean fresh list: %s", got)
	}
	freshRevocation(t, f, now, lic.Serial)
	res = c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5", Now: now})
	if res.Status != StatusRevoked {
		t.Fatalf("revoked: %s", res.Status)
	}

	freshRevocation(t, f, now.Add(-RevocationListTTL-time.Minute))
	res = c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", AppVersion: "1.5", Now: now})
	if res.Status != StatusRevocationMissing || res.RevocationChecked {
		t.Fatalf("stale list must be treated as unavailable: %+v", res)
	}
}

func TestClockRollbackRule(t *testing.T) {
	f := setup(t)
	t0 := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	opts := IssueOptions{
		DeviceID:  "device-fictional-A",
		Claims:    []Claim{{Feature: "export"}},
		NotBefore: t0.Add(-time.Hour),
		NotAfter:  t0.Add(-30 * time.Second),
	}
	tok := f.token(f.old, f.oldPriv, opts)
	freshRevocation(t, f, t0)
	c := f.checker()
	if got := c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", Now: t0, PersistClock: true}).Status; got != StatusExpired {
		t.Fatalf("baseline: %s", got)
	}
	// A rollback within tolerance is clamped to the largest observed time:
	// the license stays expired instead of gaining an extra minute.
	res := c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", Now: t0.Add(-time.Minute), PersistClock: true})
	if res.Status != StatusExpired {
		t.Fatalf("small rollback must not extend validity: %s %v", res.Status, res.Err)
	}
	if !res.CheckedAt.Equal(t0) {
		t.Fatalf("effective time clamped to %v, got %v", t0, res.CheckedAt)
	}
	// A rollback beyond the explicit tolerance fails closed.
	res = c.Check(Request{Token: tok, DeviceID: "device-fictional-A", Feature: "export", Now: t0.Add(-6 * time.Minute), PersistClock: true})
	if !errors.Is(res.Err, ErrClockRolledBack) {
		t.Fatalf("large rollback: %s %v", res.Status, res.Err)
	}
}

func TestUnsupportedFormatVersionRejected(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	l := &License{
		Version: 99, Serial: "lic_future", Issuer: f.old.Issuer, KeyID: f.old.KeyID,
		DeviceID: "device-fictional-A", Claims: []Claim{{Feature: "export"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	data, err := l.encode()
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(f.oldPriv, data)
	tok := Token(base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(sig))
	_, err = tok.parse(f.kr)
	if !errors.Is(err, ErrVersionChange) {
		t.Fatalf("version change: %v", err)
	}
}
