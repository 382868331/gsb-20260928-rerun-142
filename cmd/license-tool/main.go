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
	case "delegate":
		err = cmdDelegate(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "rev-update":
		err = cmdRevUpdate(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "check-chain":
		err = cmdCheckChain(os.Args[2:])
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
              [--delegate-key-out FILE]
  delegate    --parent FILE [--chain-in FILE] --delegator-key FILE
              --out FILE --license-id ID --features a,b --days N
  revoke      --secret FILE --out FILE --serial N --ids license1,license2
              [--merge-store FILE]
  rev-update  --keyring FILE --in FILE --store FILE
  check       --keyring FILE --license FILE --device ID --anchor FILE
              [--revocations FILE] [--rev-store FILE] [--require-revocation]
  check-chain --keyring FILE --chain FILE --device ID --anchor FILE
              [--revocations FILE] [--rev-store FILE] [--require-revocation]`)
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
	delegKeyOut := fs.String("delegate-key-out", "", "write a fresh delegation keypair that allows one restricted sub-license level")
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
	var delegKey *license.DelegationPrivate
	if *delegKeyOut != "" {
		dk, err := license.NewDelegationKey()
		if err != nil {
			return err
		}
		delegKey = dk
		l.DelegationKey = dk.Public
	}
	env, err := license.NewSigner(secret).Issue(l)
	if err != nil {
		return err
	}
	if delegKey != nil {
		if err := saveDelegationKey(*delegKeyOut, delegKey); err != nil {
			return err
		}
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
	serial := fs.Uint64("serial", 1, "monotonic sequence number; must exceed every earlier update")
	mergeStore := fs.String("merge-store", "", "durable store whose applied revoked ids are retained")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret, err := license.LoadSecret(*secretPath)
	if err != nil {
		return err
	}
	var ids []string
	if *mergeStore != "" {
		if snap := license.NewRevocationStore(*mergeStore).Snapshot(); snap != nil {
			ids = append(ids, snap.List.RevokedIDs...)
		}
	}
	for _, id := range strings.Split(*idsFlag, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	rl := license.RevocationList{
		Serial:      *serial,
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

// cmdDelegate creates one restricted sub-license level. The parent must be
// the leaf of --parent/--chain-in and must carry the matching delegation key;
// the core rejects any child that widens features, device or validity.
func cmdDelegate(args []string) error {
	fs := flag.NewFlagSet("delegate", flag.ContinueOnError)
	parentPath := fs.String("parent", "", "single parent license (root) file")
	chainIn := fs.String("chain-in", "", "existing delegation chain file; the new level is appended")
	keyPath := fs.String("delegator-key", "", "delegation private key whose public half is in the parent")
	out := fs.String("out", "chain.json", "output delegation chain")
	id := fs.String("license-id", "", "new sub-license id")
	feats := fs.String("features", "", "comma-separated feature names (subset of parent)")
	days := fs.Int("days", 30, "validity in days from --at, clipped to parent window")
	at := fs.String("at", "", "issued-at time (RFC3339), default now")
	nextKeyOut := fs.String("delegate-key-out", "", "write a fresh keypair allowing one further level under the child")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--license-id is required")
	}
	dk, err := loadDelegationKey(*keyPath)
	if err != nil {
		return err
	}

	var chain license.LicenseChain
	if *chainIn != "" {
		data, err := os.ReadFile(*chainIn)
		if err != nil {
			return err
		}
		parsed, err := license.ParseChain(data)
		if err != nil {
			return err
		}
		chain = *parsed
	} else {
		data, err := os.ReadFile(*parentPath)
		if err != nil {
			return err
		}
		env, err := license.ParseEnvelope(data)
		if err != nil {
			return err
		}
		chain.Envelopes = []license.Envelope{*env}
	}
	parent := chain.Leaf()

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
	parentNBT, err := time.Parse(time.RFC3339, parent.NotAfter)
	if err != nil {
		return err
	}
	nbt := now.AddDate(0, 0, *days)
	if nbt.After(parentNBT) {
		nbt = parentNBT
	}
	child := license.License{
		Version:   license.CurrentFormatVersion,
		LicenseID: *id,
		DeviceID:  parent.DeviceID,
		Features:  features,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		NotBefore: now.UTC().Format(time.RFC3339),
		NotAfter:  nbt.UTC().Format(time.RFC3339),
	}
	var nextKey *license.DelegationPrivate
	if *nextKeyOut != "" {
		nextKey, err = license.NewDelegationKey()
		if err != nil {
			return err
		}
		child.DelegationKey = nextKey.Public
	}
	if err := issueAndWriteChild(&chain, parent, dk, child, *out); err != nil {
		return err
	}
	if nextKey != nil {
		return saveDelegationKey(*nextKeyOut, nextKey)
	}
	return nil
}

func issueAndWriteChild(chain *license.LicenseChain, parent *license.License, dk *license.DelegationPrivate, child license.License, out string) error {
	env, err := license.IssueDelegated(parent, dk, child)
	if err != nil {
		return err
	}
	chain.Envelopes = append(chain.Envelopes, *env)
	data, err := chain.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(out, data, 0o644)
}

// cmdRevUpdate applies a signed revocation list to the durable store only
// when its serial advances the known state. Older material is rejected.
func cmdRevUpdate(args []string) error {
	fs := flag.NewFlagSet("rev-update", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	in := fs.String("in", "revocations.json", "incoming signed revocation list")
	storePath := fs.String("store", "revocation-store.json", "durable monotonic revocation state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	list, err := loadRevocations(*in)
	if err != nil {
		return err
	}
	return license.NewRevocationStore(*storePath).Apply(ring, list)
}

func cmdCheckChain(args []string) error {
	fs := flag.NewFlagSet("check-chain", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	chainPath := fs.String("chain", "chain.json", "imported delegation chain file")
	device := fs.String("device", "", "local device id")
	revocPath := fs.String("revocations", "", "signed revocation list (optional, ad-hoc)")
	storePath := fs.String("rev-store", "", "durable monotonic revocation state")
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
	data, err := os.ReadFile(*chainPath)
	if err != nil {
		return err
	}
	anchor := license.NewFileAnchor(*anchorPath)
	last, err := anchor.Last()
	if err != nil {
		return err
	}
	c := &license.Checker{Ring: ring, RequireRevocation: *requireRev}
	if *storePath != "" {
		c.Store = license.NewRevocationStore(*storePath)
	}
	if *revocPath != "" {
		r, err := loadRevocations(*revocPath)
		if err != nil {
			return err
		}
		c.Revocation = r
	}
	res, eff, err := c.CheckChainBytes(data, *device, last)
	if advErr := anchor.Advance(eff); advErr != nil {
		return advErr
	}
	depth := 0
	if res.Chain != nil {
		depth = len(res.Chain)
	}
	fmt.Printf("valid=%v depth=%d device=%q features=%v checked_at=%s clock_rolled_back=%v revocation=%s\n",
		res.Valid, depth, res.License.DeviceID, res.License.Features,
		res.CheckedAt.Format(time.RFC3339), res.ClockRolledBack, res.Revocation)
	return err
}

func saveDelegationKey(path string, dk *license.DelegationPrivate) error {
	data, err := jsonMarshal(dk)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func loadDelegationKey(path string) (*license.DelegationPrivate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var dk license.DelegationPrivate
	if err := jsonUnmarshal(data, &dk); err != nil {
		return nil, err
	}
	return &dk, nil
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
	storePath := fs.String("rev-store", "", "durable monotonic revocation state")
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
	if *storePath != "" {
		c.Store = license.NewRevocationStore(*storePath)
	}
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
