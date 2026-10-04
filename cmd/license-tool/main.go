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
	case "restriction-sign":
		err = cmdRestrictionSign(os.Args[2:])
	case "restriction-import":
		err = cmdRestrictionImport(os.Args[2:])
	case "review-usage":
		err = cmdReviewUsage(os.Args[2:])
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
  restriction-sign --secret FILE --out FILE --serial N [--merge FILE]
              --event-id ID --event-type suspend|cancel|end
              [--target ID] [--scope-license ID] [--resource docs]
              [--actions read,write] [--at RFC3339] [--not-before RFC3339]
              [--not-after RFC3339] [--canceled-at RFC3339] [--ended-at RFC3339]
  restriction-import --keyring FILE --store FILE --restrictions FILE
  review-usage --license root,...,leaf --restriction-store FILE --records FILE
  check       --keyring FILE --license FILE --device ID --anchor FILE
              [--revocations FILE | --revocation-store FILE]
              [--restrictions FILE | --restriction-store FILE]
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
	grantsFlag := fs.String("grants", "", "comma-separated resource=action,... grants")
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
		Grants:    parseGrants(*grantsFlag),
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
	grantsFlag := fs.String("grants", "", "comma-separated resource=action,... grants (subset of parent)")
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
		Grants:    parseGrants(*grantsFlag),
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

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	licensePath := fs.String("license", "license.json", "imported license file")
	device := fs.String("device", "", "local device id")
	revocPath := fs.String("revocations", "", "signed revocation list (optional)")
	storePath := fs.String("revocation-store", "", "persistent monotonic revocation store (optional)")
	restrictionPath := fs.String("restrictions", "", "signed restriction update (optional)")
	restrictionStorePath := fs.String("restriction-store", "", "persistent restriction facts store (optional)")
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
	if *restrictionPath != "" {
		data, err := os.ReadFile(*restrictionPath)
		if err != nil {
			return err
		}
		r, err := license.ParseSignedRestrictionUpdate(data)
		if err != nil {
			return err
		}
		c.Restriction = r
	}
	if *restrictionStorePath != "" {
		restrictionStore, err := license.LoadRestrictionStore(*restrictionStorePath)
		if err != nil {
			return err
		}
		c.RestrictionStore = restrictionStore
	}
	res, eff, err := c.CheckChain(chain, *device, last)
	// Advance the monotonic anchor on EVERY evaluation, including expired
	// ones: otherwise "expire, then roll the clock back" could resurrect the
	// license on the next run.
	if advErr := anchor.Advance(eff); advErr != nil {
		return advErr
	}
	fmt.Printf("valid=%v device=%q features=%v grants=%v checked_at=%s clock_rolled_back=%v revocation=%s restriction_known=%v restriction_serial=%d active_restrictions=%v\n",
		res.Valid, res.License.DeviceID, res.License.Features,
		res.AvailableGrants, res.CheckedAt.Format(time.RFC3339), res.ClockRolledBack, res.Revocation,
		res.RestrictionBasis.Known, res.RestrictionBasis.Serial, activeRestrictionIDs(res.RestrictionBasis.Active))
	return err
}

func cmdRestrictionSign(args []string) error {
	fs := flag.NewFlagSet("restriction-sign", flag.ContinueOnError)
	secretPath := fs.String("secret", "issuer.key.json", "issuer secret key")
	out := fs.String("out", "restrictions.json", "signed restriction update output")
	mergePath := fs.String("merge", "", "previous signed update whose events are retained")
	serial := fs.Int64("serial", 0, "strictly increasing restriction data version")
	eventID := fs.String("event-id", "", "new event id")
	eventType := fs.String("event-type", "", "suspend, cancel, or end")
	targetID := fs.String("target", "", "target suspension event id for cancel/end")
	scopeLicense := fs.String("scope-license", "", "license id whose subtree is restricted (empty means chain-wide)")
	resource := fs.String("resource", "", "restricted resource")
	actionsFlag := fs.String("actions", "", "comma-separated restricted operations")
	at := fs.String("at", "", "event record time (RFC3339), default now")
	notBefore := fs.String("not-before", "", "suspension start")
	notAfter := fs.String("not-after", "", "suspension end, exclusive")
	canceledAt := fs.String("canceled-at", "", "time a not-yet-started suspension is canceled")
	endedAt := fs.String("ended-at", "", "time an active suspension ends")
	reason := fs.String("reason", "", "human-readable reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret, err := license.LoadSecret(*secretPath)
	if err != nil {
		return err
	}
	var events []license.RestrictionEvent
	if *mergePath != "" {
		old, err := loadRestrictions(*mergePath)
		if err != nil {
			return err
		}
		events = append(events, old.Update.Events...)
	}
	event := license.RestrictionEvent{
		EventID:  *eventID,
		Type:     *eventType,
		TargetID: *targetID,
		Scope: license.RestrictionScope{
			LicenseID: *scopeLicense,
			Resource:  *resource,
			Actions:   parseCSV(*actionsFlag),
		},
		Reason: *reason,
	}
	if event.NotBefore, err = parseRFC3339OrZero(*notBefore); err != nil {
		return err
	}
	if event.NotAfter, err = parseRFC3339OrZero(*notAfter); err != nil {
		return err
	}
	if event.EndedAt, err = parseRFC3339OrZero(*endedAt); err != nil {
		return err
	}
	if event.CanceledAt, err = parseRFC3339OrZero(*canceledAt); err != nil {
		return err
	}
	events = append(events, event)
	generated := time.Now().UTC()
	if *at != "" {
		generated, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	signed, err := license.SignRestrictionUpdate(secret, license.RestrictionUpdate{
		Serial: *serial, GeneratedAt: generated, Events: events,
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

func cmdRestrictionImport(args []string) error {
	fs := flag.NewFlagSet("restriction-import", flag.ContinueOnError)
	ringPath := fs.String("keyring", "keyring.json", "trusted public key ring")
	storePath := fs.String("store", "restriction-store.json", "local restriction store")
	restrictionPath := fs.String("restrictions", "", "signed restriction update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ring, err := license.LoadKeyRing(*ringPath)
	if err != nil {
		return err
	}
	update, err := loadRestrictions(*restrictionPath)
	if err != nil {
		return err
	}
	store, err := license.LoadRestrictionStore(*storePath)
	if err != nil {
		return err
	}
	if err := store.Import(ring, update); err != nil {
		return err
	}
	fmt.Printf("imported issuer=%s serial=%d events=%d\n", update.Update.IssuerID, update.Update.Serial, len(update.Update.Events))
	return nil
}

func cmdReviewUsage(args []string) error {
	fs := flag.NewFlagSet("review-usage", flag.ContinueOnError)
	licensePath := fs.String("license", "", "comma-separated root-to-leaf chain")
	storePath := fs.String("restriction-store", "restriction-store.json", "local restriction store")
	recordsPath := fs.String("records", "", "JSON array of license.UsageRecord values")
	if err := fs.Parse(args); err != nil {
		return err
	}
	chain, err := loadChain(*licensePath)
	if err != nil {
		return err
	}
	store, err := license.LoadRestrictionStore(*storePath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*recordsPath)
	if err != nil {
		return err
	}
	var records []license.UsageRecord
	if err := jsonUnmarshal(data, &records); err != nil {
		return err
	}
	findings := store.ReviewUsage(chain, records)
	data, err = jsonMarshalIndent(findings)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(data, '\n'))
	return err
}

func loadRestrictions(path string) (*license.SignedRestrictionUpdate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return license.ParseSignedRestrictionUpdate(data)
}

func loadChain(path string) ([]*license.Envelope, error) {
	var chain []*license.Envelope
	for _, part := range strings.Split(path, ",") {
		data, err := os.ReadFile(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		env, err := license.ParseEnvelope(data)
		if err != nil {
			return nil, err
		}
		chain = append(chain, env)
	}
	if len(chain) == 0 {
		return nil, license.ErrMalformedLicense
	}
	return chain, nil
}

func parseGrants(in string) []license.Grant {
	byResource := map[string][]string{}
	var order []string
	for _, item := range parseCSV(in) {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if _, ok := byResource[parts[0]]; !ok {
			order = append(order, parts[0])
		}
		byResource[parts[0]] = append(byResource[parts[0]], parts[1])
	}
	var grants []license.Grant
	for _, resource := range order {
		grants = append(grants, license.Grant{Resource: resource, Actions: dedupe(byResource[resource])})
	}
	return grants
}

func parseCSV(in string) []string {
	var out []string
	for _, item := range strings.Split(in, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseRFC3339OrZero(in string) (time.Time, error) {
	if in == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, in)
}

func activeRestrictionIDs(events []license.RestrictionEvent) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	return ids
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
