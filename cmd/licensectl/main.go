// Command licensectl drives the offline license core: key generation and
// rotation, issuing, importing, revocation snapshot creation and checking.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	license "softlicense"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "issue":
		err = issue(os.Args[2:])
	case "import":
		err = importLic(os.Args[2:])
	case "revoke":
		err = revoke(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: licensectl keygen|issue|import|revoke|check [flags]")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyDir := fs.String("keydir", "./issuer", "issuer private key directory")
	trustDir := fs.String("trustdir", "./trust", "verifier trust/state directory")
	issuer := fs.String("issuer", "project-temp-issuer", "issuer name")
	_ = fs.Parse(args)
	k, priv, err := license.GenerateIssuerKey(*issuer)
	if err != nil {
		return err
	}
	if err := license.SaveIssuerKey(*keyDir, k, priv); err != nil {
		return err
	}
	kr, _ := license.LoadKeyring(*trustDir)
	if kr == nil {
		kr = license.NewKeyring()
	}
	kr.Add(k)
	return license.SaveKeyring(*trustDir, kr)
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	keyDir := fs.String("keydir", "./issuer", "issuer private key directory")
	device := fs.String("device", "", "bound device identity")
	features := fs.String("features", "", "comma-separated feature[@minVersion:maxVersion]")
	days := fs.Int("days", 30, "validity duration in days")
	out := fs.String("out", "", "token output file (default stdout)")
	nowArg := fs.String("now", "", "fixed issue time RFC3339")
	_ = fs.Parse(args)
	if *device == "" || *features == "" {
		return fmt.Errorf("-device and -features are required")
	}
	k, priv, err := license.LoadNewestIssuerKey(*keyDir)
	if err != nil {
		return err
	}
	now, err := parseNow(*nowArg, time.Now())
	if err != nil {
		return err
	}
	tok, err := license.NewSigner(k, priv).Issue(license.IssueOptions{
		DeviceID:  *device,
		Claims:    parseFeatures(*features),
		NotBefore: now,
		NotAfter:  now.Add(time.Duration(*days) * 24 * time.Hour),
		IssuedAt:  now,
	})
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(tok)
		return nil
	}
	return os.WriteFile(*out, []byte(tok), 0o600)
}

func importLic(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	trustDir := fs.String("trustdir", "./trust", "verifier trust/state directory")
	file := fs.String("file", "", "license token file")
	_ = fs.Parse(args)
	kr, err := license.LoadKeyring(*trustDir)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	serial, err := license.NewChecker(kr, *trustDir).Import(license.Token(strings.TrimSpace(string(data))))
	if err != nil {
		return err
	}
	fmt.Println(serial)
	return nil
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	keyDir := fs.String("keydir", "./issuer", "issuer private key directory")
	trustDir := fs.String("trustdir", "./trust", "verifier trust/state directory")
	serials := fs.String("serials", "", "comma-separated revoked license serials")
	out := fs.String("out", "", "output file (default trustdir/revocation.json)")
	_ = fs.Parse(args)
	k, priv, err := license.LoadNewestIssuerKey(*keyDir)
	if err != nil {
		return err
	}
	var list []string
	for _, s := range strings.Split(*serials, ",") {
		if s = strings.TrimSpace(s); s != "" {
			list = append(list, s)
		}
	}
	tok, err := license.SignRevocationList(k, priv, list, time.Now())
	if err != nil {
		return err
	}
	path := *out
	if path == "" {
		path = filepath.Join(*trustDir, "revocation.json")
	}
	return license.SaveRevocationToken(path, tok)
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	trustDir := fs.String("trustdir", "./trust", "verifier trust/state directory")
	file := fs.String("file", "", "license token file")
	serial := fs.String("serial", "", "check an imported license by serial")
	device := fs.String("device", "", "current device identity")
	feature := fs.String("feature", "", "requested feature")
	appVersion := fs.String("app-version", "", "application semantic version")
	nowArg := fs.String("now", "", "fixed check time RFC3339")
	skipRev := fs.Bool("insecure-skip-revocation", false, "do not require a fresh revocation list")
	_ = fs.Parse(args)
	kr, err := license.LoadKeyring(*trustDir)
	if err != nil {
		return err
	}
	checker := license.NewChecker(kr, *trustDir)
	var tok license.Token
	if *serial != "" {
		tok, err = checker.LoadImported(*serial)
	} else if *file != "" {
		var data []byte
		data, err = os.ReadFile(*file)
		tok = license.Token(strings.TrimSpace(string(data)))
	} else {
		return fmt.Errorf("either -file or -serial is required")
	}
	if err != nil {
		return err
	}
	now, err := parseNow(*nowArg, time.Now())
	if err != nil {
		return err
	}
	res := checker.Check(license.Request{
		Token:          tok,
		DeviceID:       *device,
		Feature:        *feature,
		AppVersion:     *appVersion,
		Now:            now,
		SkipRevocation: *skipRev,
	})
	out := map[string]any{
		"status":             string(res.Status),
		"granted":            res.Granted(),
		"revocation_checked": res.RevocationChecked,
	}
	if res.Err != nil {
		out["error"] = res.Err.Error()
	}
	if res.License != nil {
		out["serial"] = res.License.Serial
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func parseNow(s string, fallback time.Time) (time.Time, error) {
	if s == "" {
		return fallback, nil
	}
	return time.Parse(time.RFC3339, s)
}

func parseFeatures(spec string) []license.Claim {
	var claims []license.Claim
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		c := license.Claim{Feature: item}
		if at := strings.Index(item, "@"); at >= 0 {
			c.Feature = item[:at]
			rangeSpec := item[at+1:]
			parts := strings.SplitN(rangeSpec, ":", 2)
			c.MinVersion = parts[0]
			if len(parts) == 2 {
				c.MaxVersion = parts[1]
			}
		}
		claims = append(claims, c)
	}
	return claims
}
