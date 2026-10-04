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
	case "issue-delegated":
		err = cmdIssueDelegated(os.Args[2:])
	case "gen-delegator":
		err = cmdGenDelegator(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "revoke-import":
		err = cmdRevokeImport(os.Args[2:])
	case "suspend":
		err = cmdSuspend(os.Args[2:])
	case "suspend-import":
		err = cmdSuspendImport(os.Args[2:])
	case "usage-review":
		err = cmdUsageReview(os.Args[2:])
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
              [--delegator-key FILE]  (embed key allowing sublicensing)
  gen-delegator --key FILE           (fresh temporary delegation keypair)
  issue-delegated --key FILE --parent FILE --issuer ID --out FILE
              --license-id ID --device ID --features a,b --days N
              [--delegator-key FILE] [--at RFC3339]
  revoke      --secret FILE --out FILE --ids license1,license2 [--merge FILE]
              [--serial N]
  revoke-import --keyring FILE --store FILE --revocations FILE
  suspend     --secret FILE --out FILE --records FILE [--merge FILE]
              [--serial N] [--at RFC3339]
              (records file: JSON array of suspension records; kinds:
               suspend / cancel-scheduled / end-early)
  suspend-import --keyring FILE --store FILE --suspensions FILE
  usage-review --store FILE --usage FILE
              (usage file: JSON array of records with license_id, feature,
               operation, time; prints which past usages need review
               under the currently confirmed restriction basis)
  check       --keyring FILE --license FILE --device ID --anchor FILE
              [--revocations FILE | --revocation-store FILE]
              [--suspensions FILE | --suspension-store FILE]
              [--require-revocation]
              (--license accepts a comma-separated root-to-leaf chain)`)
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
	delegatorPath := fs.String("delegator-key", "", "temporary delegator public key to embed")
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
	if *delegatorPath != "" {
		dk, err := loadDelegationKey(*delegatorPath)
		if err != nil {
			return err
		}
		l.Delegators = []license.DelegationKey{dk.DelegationKey}
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

func cmdGenDelegator(args []string) error {
	fs := flag.NewFlagSet("gen-delegator", flag.ContinueOnError)
	keyPath := fs.String("key", "delegator.key.json", "delegation key output")
	id := fs.String("id", fmt.Sprintf("dk-%d", time.Now().UnixNano()), "delegator key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dk, err := license.NewDelegationKey(*id)
	if err != nil {
		return err
	}
	data, err := jsonMarshalIndent(dk)
	if err != nil {
		return err
	}
	return os.WriteFile(*keyPath, data, 0o600)
}

func loadDelegationKey(path string) (*license.DelegationSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var dk license.DelegationSecret
	if err := jsonUnmarshal(data, &dk); err != nil {
		return nil, err
	}
	return &dk, nil
}

func cmdIssueDelegated(args []string) error {
	fs := flag.NewFlagSet("issue-delegated", flag.ContinueOnError)
	keyPath := fs.String("key", "delegator.key.json", "delegation secret key")
	parentPath := fs.String("parent", "", "parent license envelope (file to restrict)")
	issuer := fs.String("issuer", "", "root issuer id of the chain")
	out := fs.String("out", "sublicense.json", "output file")
	id := fs.String("license-id", "", "unique sublicense id")
	device := fs.String("device", "", "bound device id (must equal parent's)")
	feats := fs.String("features", "", "comma-separated feature names (subset of parent)")
	days := fs.Int("days", 365, "validity in days (must fit inside parent window)")
	at := fs.String("at", "", "issued-at time (RFC3339), default now")
	delegatorPath := fs.String("delegator-key", "", "optional next-level delegator key to embed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *parentPath == "" || *issuer == "" || *id == "" || *device == "" {
		return fmt.Errorf("--parent, --issuer, --license-id and --device are required")
	}
	dk, err := loadDelegationKey(*keyPath)
	if err != nil {
		return err
	}
	parentData, err := os.ReadFile(*parentPath)
	if err != nil {
		return err
	}
	parentEnv, err := license.ParseEnvelope(parentData)
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
	parentNbt, err := time.Parse(time.RFC3339, parentEnv.License.NotAfter)
	if err != nil {
		return err
	}
	var features []string
	for _, f := range strings.Split(*feats, ",") {
		if f = strings.TrimSpace(f); f != "" {
			features = append(features, f)
		}
	}
	notAfter := now.AddDate(0, 0, *days).UTC()
	if notAfter.After(parentNbt) {
		notAfter = parentNbt
	}
	l := license.License{
		Version:   license.CurrentFormatVersion,
		LicenseID: *id,
		DeviceID:  *device,
		Features:  features,
		IssuedAt:  now.UTC().Format(time.RFC3339),
		NotBefore: now.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.Format(time.RFC3339),
	}
	if *delegatorPath != "" {
		next, err := loadDelegationKey(*delegatorPath)
		if err != nil {
			return err
		}
		l.Delegators = []license.DelegationKey{next.DelegationKey}
	}
	env, err := license.NewDelegationSigner(dk, *issuer).Issue(l, &parentEnv.License)
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
	serial := fs.Int64("serial", 0, "strictly increasing revocation data version")
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

func cmdRevokeImport(args []string) error {
	// Verifies the signed list against the trusted ring and applies it to
	// the persistent store only when its serial is strictly newer. Older or
	// non-cumulative data is rejected and changes nothing.
	fs := flag.NewFlagSet("revoke-import", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	storePath := fs.String("store", "revocation-store.json", "local revocation state store")
	revocPath := fs.String("revocations", "", "signed revocation list to import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *revocPath == "" {
		return fmt.Errorf("--revocations is required")
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	list, err := loadRevocations(*revocPath)
	if err != nil {
		return err
	}
	store, err := license.LoadRevocationStore(*storePath)
	if err != nil {
		return err
	}
	if err := store.Import(ring, list); err != nil {
		return err
	}
	fmt.Printf("imported issuer=%s serial=%d revoked=%v\n",
		list.List.IssuerID, list.List.Serial, list.List.RevokedIDs)
	return nil
}

func cmdSuspend(args []string) error {
	fs := flag.NewFlagSet("suspend", flag.ContinueOnError)
	secretPath := fs.String("secret", "issuer.key.json", "issuer secret key")
	out := fs.String("out", "suspensions.json", "signed suspension list output")
	recordsPath := fs.String("records", "", "JSON array of suspension records")
	merge := fs.String("merge", "", "existing list whose records are retained")
	serial := fs.Int64("serial", 0, "strictly increasing suspension data version")
	at := fs.String("at", "", "generated-at time (RFC3339), default now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *recordsPath == "" && *merge == "" {
		return fmt.Errorf("--records and/or --merge are required")
	}
	secret, err := license.LoadSecret(*secretPath)
	if err != nil {
		return err
	}
	gen := time.Now().UTC()
	if *at != "" {
		gen, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	var records []license.SuspensionRecord
	if *merge != "" {
		old, err := loadSuspensions(*merge)
		if err != nil {
			return err
		}
		records = append(records, old.List.Records...)
	}
	if *recordsPath != "" {
		data, err := os.ReadFile(*recordsPath)
		if err != nil {
			return err
		}
		var extra []license.SuspensionRecord
		if err := jsonUnmarshal(data, &extra); err != nil {
			return err
		}
		records = append(records, extra...)
	}
	signed, err := license.SignSuspensionList(secret, license.SuspensionList{
		Serial:      *serial,
		GeneratedAt: gen.Format(time.RFC3339),
		Records:     records,
	})
	if err != nil {
		return err
	}
	data, err := signed.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func loadSuspensions(path string) (*license.SignedSuspensionList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s license.SignedSuspensionList
	if err := jsonUnmarshal(data, &s); err != nil {
		return nil, license.ErrMalformedSuspensionList
	}
	return &s, nil
}

func cmdSuspendImport(args []string) error {
	// Verifies the signed list and applies it only when strictly newer;
	// stale or non-cumulative data is rejected and changes nothing.
	fs := flag.NewFlagSet("suspend-import", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	storePath := fs.String("store", "suspension-store.json", "local suspension state store")
	suspPath := fs.String("suspensions", "", "signed suspension list to import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *suspPath == "" {
		return fmt.Errorf("--suspensions is required")
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	list, err := loadSuspensions(*suspPath)
	if err != nil {
		return err
	}
	store, err := license.LoadSuspensionStore(*storePath)
	if err != nil {
		return err
	}
	if err := store.Import(ring, list); err != nil {
		return err
	}
	fmt.Printf("imported issuer=%s serial=%d records=%d\n",
		list.List.IssuerID, list.List.Serial, len(list.List.Records))
	return nil
}

func cmdUsageReview(args []string) error {
	// Re-states, against the newest confirmed basis, which existing usage
	// records need review. A usage is flagged only when it falls inside a
	// fact's effective interval; later-effective restrictions never reach
	// back and rewrite earlier usage.
	fs := flag.NewFlagSet("usage-review", flag.ContinueOnError)
	storePath := fs.String("store", "suspension-store.json", "local suspension state store")
	usagePath := fs.String("usage", "", "JSON array of usage records")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *usagePath == "" {
		return fmt.Errorf("--usage is required")
	}
	store, err := license.LoadSuspensionStore(*storePath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*usagePath)
	if err != nil {
		return err
	}
	var usages []license.UsageRecord
	if err := jsonUnmarshal(data, &usages); err != nil {
		return err
	}
	items := store.Review(usages)
	for _, it := range items {
		fmt.Printf("review license=%s feature=%s operation=%s used_at=%s fact=%s serial=%d interval=%s..%s\n",
			it.Usage.LicenseID, it.Usage.Feature, it.Usage.Operation,
			it.Usage.Time.UTC().Format(time.RFC3339),
			it.Fact.RecordID, it.Fact.Serial, it.Fact.NotBefore, it.Fact.NotAfter)
	}
	fmt.Printf("review_items=%d\n", len(items))
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	licensePath := fs.String("license", "license.json", "imported license file")
	device := fs.String("device", "", "local device id")
	revocPath := fs.String("revocations", "", "signed revocation list (optional)")
	storePath := fs.String("revocation-store", "", "persistent monotonic revocation store (optional)")
	suspPath := fs.String("suspensions", "", "signed suspension list (optional)")
	suspStorePath := fs.String("suspension-store", "", "persistent monotonic suspension store (optional)")
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
	var chain []*license.Envelope
	for _, part := range strings.Split(*licensePath, ",") {
		data, err := os.ReadFile(strings.TrimSpace(part))
		if err != nil {
			return err
		}
		env, err := license.ParseEnvelope(data)
		if err != nil {
			return err
		}
		chain = append(chain, env)
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
	if *storePath != "" {
		store, err := license.LoadRevocationStore(*storePath)
		if err != nil {
			return err
		}
		c.RevocationStore = store
	}
	if *suspPath != "" {
		s, err := loadSuspensions(*suspPath)
		if err != nil {
			return err
		}
		c.Suspensions = s
	}
	if *suspStorePath != "" {
		store, err := license.LoadSuspensionStore(*suspStorePath)
		if err != nil {
			return err
		}
		c.SuspensionStore = store
	}
	res, eff, err := c.CheckChain(chain, *device, last)
	// Advance the monotonic anchor on EVERY evaluation, including expired
	// ones: otherwise "expire, then roll the clock back" could resurrect the
	// license on the next run.
	if advErr := anchor.Advance(eff); advErr != nil {
		return advErr
	}
	fmt.Printf("valid=%v device=%q features=%v effective_features=%v suspended=%v checked_at=%s clock_rolled_back=%v revocation=%s suspensions_known=%v\n",
		res.Valid, res.License.DeviceID, res.License.Features,
		res.EffectiveFeatures, res.SuspendedFeatures,
		res.CheckedAt.Format(time.RFC3339), res.ClockRolledBack, res.Revocation, res.SuspensionsKnown)
	for _, f := range res.Restrictions {
		fmt.Printf("restriction record=%s serial=%d license=%s features=%v operations=%v interval=%s..%s\n",
			f.RecordID, f.Serial, f.LicenseID, f.Features, f.Operations, f.NotBefore, f.NotAfter)
	}
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
