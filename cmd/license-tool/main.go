// Command license-tool is a small offline CLI around the license core. It
// generates temporary project keys, issues/imports/checks licenses and signs
// revocation lists. It never contacts any commercial licensing service.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"licensecore/license"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init-issuer":
		err = cmdInitIssuer(os.Args[2:])
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: license-tool <command> [flags]
commands:
  init-issuer --issuer ID --keyring FILE --secret FILE
  rotate      --issuer ID --keyring FILE --secret FILE
  issue       --secret FILE --out FILE --license-id ID --device ID
              --features a,b --days N [--at RFC3339]
  revoke      --secret FILE --out FILE --ids license1,license2 [--merge FILE]
  check       --keyring FILE --license FILE --device ID --anchor FILE
              [--revocations FILE] [--require-revocation]`)
}

func cmdInitIssuer(args []string) error {
	fs := flag.NewFlagSet("init-issuer", flag.ContinueOnError)
	issuer := fs.String("issuer", "local-dev", "issuer identifier")
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	secretPath := fs.String("secret", "issuer.key.json", "secret key output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := license.NewIssuerKey(*issuer, "k1")
	if err != nil {
		return err
	}
	if err := license.SaveSecret(*secretPath, key); err != nil {
		return err
	}
	ring := license.NewKeyRing(key.IssuerPublic)
	_ = os.Remove(*ringPath)
	return license.SaveKeyRing(*ringPath, ring)
}

func cmdRotate(args []string) error {
	// Rotation generates a new key and ADDS it to the ring; old keys stay so
	// licenses already issued remain verifiable until they expire.
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	issuer := fs.String("issuer", "local-dev", "issuer identifier")
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	secretPath := fs.String("secret", "issuer.key.json", "new secret key output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	keyID := fmt.Sprintf("k%d", time.Now().UnixNano())
	key, err := license.NewIssuerKey(*issuer, keyID)
	if err != nil {
		return err
	}
	ring.Add(key.IssuerPublic)
	if err := license.SaveSecret(*secretPath, key); err != nil {
		return err
	}
	return license.SaveKeyRing(*ringPath, ring)
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	secretPath := fs.String("secret", "issuer.key.json", "issuer secret key")
	out := fs.String("out", "license.json", "license output")
	id := fs.String("license-id", "", "unique license id")
	device := fs.String("device", "", "bound device id")
	feats := fs.String("features", "", "comma-separated feature names")
	days := fs.Int("days", 365, "validity in days")
	at := fs.String("at", "", "issued-at time (RFC3339), default now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *device == "" {
		return fmt.Errorf("--license-id and --device are required")
	}
	secret, err := license.LoadSecret(*secretPath)
	if err != nil {
		return err
	}
	now := time.Now()
	if *at != "" {
		now, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	var features []string
	for _, f := range strings.Split(*feats, ",") {
		if f = strings.TrimSpace(f); f != "" {
			features = append(features, f)
		}
	}
	l := license.License{
		Version:   license.CurrentFormatVersion,
		LicenseID: *id,
		DeviceID:  *device,
		Features:  features,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		NotBefore: now.UTC().Format(time.RFC3339),
		NotAfter:  now.AddDate(0, 0, *days).UTC().Format(time.RFC3339),
	}
	env, err := license.NewSigner(secret).Issue(l)
	if err != nil {
		return err
	}
	data, err := env.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	secretPath := fs.String("secret", "issuer.key.json", "issuer secret key")
	out := fs.String("out", "revocations.json", "signed revocation list output")
	idsFlag := fs.String("ids", "", "comma-separated license ids to revoke")
	merge := fs.String("merge", "", "existing list whose revoked ids are retained")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret, err := license.LoadSecret(*secretPath)
	if err != nil {
		return err
	}
	var ids []string
	if *merge != "" {
		old, err := loadRevocations(*merge)
		if err != nil {
			return err
		}
		ids = append(ids, old.List.RevokedIDs...)
	}
	for _, id := range strings.Split(*idsFlag, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	rl := license.RevocationList{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		RevokedIDs:  dedupe(ids),
	}
	signed, err := license.SignRevocationList(secret, rl)
	if err != nil {
		return err
	}
	data, err := signed.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func loadRevocations(path string) (*license.SignedRevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s license.SignedRevocationList
	if err := jsonUnmarshal(data, &s); err != nil {
		return nil, license.ErrMalformedRevocationList
	}
	return &s, nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	licensePath := fs.String("license", "license.json", "imported license file")
	device := fs.String("device", "", "local device id")
	revocPath := fs.String("revocations", "", "signed revocation list (optional)")
	requireRev := fs.Bool("require-revocation", false, "fail when revocation data is missing")
	anchorPath := fs.String("anchor", "anchor.txt", "per-device monotonic time anchor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device == "" {
		return fmt.Errorf("--device is required")
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*licensePath)
	if err != nil {
		return err
	}
	anchor := license.NewFileAnchor(*anchorPath)
	last, err := anchor.Last()
	if err != nil {
		return err
	}
	c := &license.Checker{Ring: ring, RequireRevocation: *requireRev}
	if *revocPath != "" {
		r, err := loadRevocations(*revocPath)
		if err != nil {
			return err
		}
		c.Revocation = r
	}
	res, eff, err := c.CheckBytes(data, *device, last)
	// Advance the monotonic anchor on EVERY evaluation, including expired
	// ones: otherwise "expire, then roll the clock back" could resurrect the
	// license on the next run.
	if advErr := anchor.Advance(eff); advErr != nil {
		return advErr
	}
	fmt.Printf("valid=%v device=%q features=%v checked_at=%s clock_rolled_back=%v revocation=%s\n",
		res.Valid, res.License.DeviceID, res.License.Features,
		res.CheckedAt.Format(time.RFC3339), res.ClockRolledBack, res.Revocation)
	return err
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
