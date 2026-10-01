package license

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// helper: issue a root license, optionally carrying a delegation key.
func rootLicense(t *testing.T, key *IssuerSecret, dk *DelegationPrivate, device, id string, feats []string, nbf, nbt time.Time) *Envelope {
	t.Helper()
	l := License{
		Version: CurrentFormatVersion, LicenseID: id, DeviceID: device, Features: feats,
		IssuedAt: nbf.Format(time.RFC3339), NotBefore: nbf.Format(time.RFC3339),
		NotAfter: nbt.Format(time.RFC3339),
	}
	if dk != nil {
		l.DelegationKey = dk.Public
	}
	env, err := NewSigner(key).Issue(l)
	if err != nil {
		t.Fatalf("issue root: %v", err)
	}
	return env
}

func childLicense(id, device string, feats []string, nbf, nbt time.Time, nextKey []byte) License {
	return License{
		Version: CurrentFormatVersion, LicenseID: id, DeviceID: device, Features: feats,
		IssuedAt: nbf.Format(time.RFC3339), NotBefore: nbf.Format(time.RFC3339),
		NotAfter: nbt.Format(time.RFC3339), DelegationKey: nextKey,
	}
}

func TestMultiLevelDelegation(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	dk1, _ := NewDelegationKey()
	dk2, _ := NewDelegationKey()
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	root := rootLicense(t, key, dk1, fictionalDeviceA, "root", []string{"print", "scan", "fax"}, nbf, nbf.Add(60*24*time.Hour))
	mid := childLicense("mid", fictionalDeviceA, []string{"print", "scan"}, nbf.Add(24*time.Hour), nbf.Add(40*24*time.Hour), dk2.Public)
	midEnv, err := IssueDelegated(&root.License, dk1, mid)
	if err != nil {
		t.Fatalf("issue mid: %v", err)
	}
	leaf := childLicense("leaf", fictionalDeviceA, []string{"print"}, nbf.Add(25*time.Hour), nbf.Add(39*24*time.Hour), nil)
	leafEnv, err := IssueDelegated(&midEnv.License, dk2, leaf)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	chain := &LicenseChain{Envelopes: []Envelope{*root, *midEnv, *leafEnv}}

	ring := NewKeyRing(key.IssuerPublic)
	c := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(30 * 24 * time.Hour)}}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if err != nil || !res.Valid {
		t.Fatalf("3-level chain: %v valid=%v", err, res.Valid)
	}
	if len(res.Chain) != 3 || res.License.LicenseID != "leaf" {
		t.Fatalf("unexpected chain result: %+v", res.Chain)
	}
	if res.HasFeature("scan") {
		t.Fatalf("leaf must only carry print, got %v", res.License.Features)
	}

	// Round trip through the serialized import form.
	data, _ := chain.Encode()
	parsed, err := ParseChain(data)
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if _, _, err := c.CheckChain(parsed, fictionalDeviceA, time.Time{}); err != nil {
		t.Fatalf("reparsed chain: %v", err)
	}
}

func TestSublicenseCannotExpandScope(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	dk, _ := NewDelegationKey()
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	nbt := nbf.Add(30 * 24 * time.Hour)
	root := rootLicense(t, key, dk, fictionalDeviceA, "root", []string{"print", "scan"}, nbf, nbt)

	// Extra feature not in the parent.
	bad := childLicense("c1", fictionalDeviceA, []string{"print", "admin"}, nbf, nbt, nil)
	if _, err := IssueDelegated(&root.License, dk, bad); !errors.Is(err, ErrDelegationExpandsScope) {
		t.Fatalf("feature expansion: got %v", err)
	}
	// Different device.
	bad = childLicense("c2", fictionalDeviceB, []string{"print"}, nbf, nbt, nil)
	if _, err := IssueDelegated(&root.License, dk, bad); !errors.Is(err, ErrDelegationExpandsScope) {
		t.Fatalf("device expansion: got %v", err)
	}
	// Validity reaching beyond the parent window.
	bad = childLicense("c3", fictionalDeviceA, []string{"print"}, nbf, nbt.Add(time.Hour), nil)
	if _, err := IssueDelegated(&root.License, dk, bad); !errors.Is(err, ErrDelegationExpandsScope) {
		t.Fatalf("time expansion: got %v", err)
	}
	// Starting before the parent window.
	bad = childLicense("c4", fictionalDeviceA, []string{"print"}, nbf.Add(-time.Hour), nbf.Add(time.Hour), nil)
	if _, err := IssueDelegated(&root.License, dk, bad); !errors.Is(err, ErrDelegationExpandsScope) {
		t.Fatalf("time backstart: got %v", err)
	}

	// Parent without a delegation key cannot be delegated.
	flat := rootLicense(t, key, nil, fictionalDeviceA, "flat", []string{"print"}, nbf, nbt)
	if _, err := IssueDelegated(&flat.License, dk, childLicense("c5", fictionalDeviceA, []string{"print"}, nbf, nbt, nil)); !errors.Is(err, ErrDelegationNotPermitted) {
		t.Fatalf("no delegation key: got %v", err)
	}
	// Wrong delegator key.
	other, _ := NewDelegationKey()
	if _, err := IssueDelegated(&root.License, other, childLicense("c6", fictionalDeviceA, []string{"print"}, nbf, nbt, nil)); !errors.Is(err, ErrDelegationNotPermitted) {
		t.Fatalf("foreign delegator key: got %v", err)
	}
}

func TestDelegationForgeryAndTamperRejected(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	dk, _ := NewDelegationKey()
	foreign, _ := NewDelegationKey()
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	root := rootLicense(t, key, dk, fictionalDeviceA, "root", []string{"print"}, nbf, nbf.Add(30*24*time.Hour))

	// A properly scoped child signed by a foreign delegation key must fail
	// verification. IssueDelegated refuses mismatched keys, so craft the
	// envelope directly to make sure verification is the real boundary.
	child := childLicense("child", fictionalDeviceA, []string{"print"}, nbf, nbf.Add(24*time.Hour), nil)
	child.IssuerID = key.IssuerID
	body, _ := signingBytes(&child)
	forged := &Envelope{License: child, Signature: ed25519.Sign(ed25519.PrivateKey(foreign.Secret), body)}
	chain := &LicenseChain{Envelopes: []Envelope{*root, *forged}}
	c := &Checker{Ring: NewKeyRing(key.IssuerPublic), Clock: &fakeClock{nbf.Add(time.Hour)}}
	if _, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrDelegationSignature) {
		t.Fatalf("forged delegation: got %v", err)
	}

	// Tampering a child after signing widens scope and breaks the signature.
	good, err := IssueDelegated(&root.License, dk, child)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *good
	tampered.License.Features = []string{"admin"}
	chain = &LicenseChain{Envelopes: []Envelope{*root, tampered}}
	if _, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrDelegationSignature) {
		t.Fatalf("child tamper: got %v", err)
	}

	// Claiming an issuer key id on a child cannot elevate it to a root.
	swapped := *good
	swapped.License.KeyID = key.KeyID
	chain = &LicenseChain{Envelopes: []Envelope{*root, swapped}}
	if _, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrDelegationSignature) {
		t.Fatalf("child with issuer key id: got %v", err)
	}
}

func TestParentFailureInvalidatesChain(t *testing.T) {
	key, _ := NewIssuerKey("iss", "k1")
	dk, _ := NewDelegationKey()
	nbf := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	// Parent window ends earlier; the child still looks time-valid after.
	rootEnv := rootLicense(t, key, dk, fictionalDeviceA, "root", []string{"print", "scan"}, nbf, nbf.Add(10*24*time.Hour))
	child, err := IssueDelegated(&rootEnv.License, dk, childLicense("child", fictionalDeviceA, []string{"print"}, nbf, nbf.Add(10*24*time.Hour), nil))
	if err != nil {
		t.Fatal(err)
	}
	chain := &LicenseChain{Envelopes: []Envelope{*rootEnv, *child}}
	ring := NewKeyRing(key.IssuerPublic)

	// Parent expired -> the still-in-window child is rejected too.
	c := &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(20 * 24 * time.Hour)}}
	if _, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("parent expiry: got %v", err)
	}

	// Parent revoked -> the clean child cannot be used.
	rev, _ := SignRevocationList(key, RevocationList{Serial: 1, RevokedIDs: []string{"root"}})
	c = &Checker{Ring: ring, Clock: &fakeClock{nbf.Add(time.Hour)}, Revocation: rev}
	res, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{})
	if !errors.Is(err, ErrRevoked) || res.Revocation != Revoked {
		t.Fatalf("parent revocation: err=%v state=%s", err, res.Revocation)
	}

	// Revoking the child alone also invalidates the chain.
	rev2, _ := SignRevocationList(key, RevocationList{Serial: 2, RevokedIDs: []string{"child"}})
	c.Revocation = rev2
	if _, _, err := c.CheckChain(chain, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("child revocation: got %v", err)
	}

	// Device mismatch at any level fails the chain.
	if _, _, err := c.CheckChain(chain, fictionalDeviceB, time.Time{}); !errors.Is(err, ErrDeviceMismatch) {
		t.Fatalf("chain device: got %v", err)
	}

	// Duplicate ids (looped/replayed chain) are rejected.
	loop := &LicenseChain{Envelopes: []Envelope{*rootEnv, *rootEnv}}
	if _, _, err := c.CheckChain(loop, fictionalDeviceA, time.Time{}); !errors.Is(err, ErrDuplicateLicenseID) {
		t.Fatalf("duplicate id: got %v", err)
	}
}
