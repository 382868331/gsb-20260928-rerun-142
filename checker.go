package license

import (
	"os"
	"path/filepath"
	"time"
)

// Status is the precise outcome of a check. Applications should branch on it.
type Status string

const (
	StatusGranted           Status = "granted"
	StatusExpired           Status = "expired"
	StatusNotYetValid       Status = "not_yet_valid"
	StatusDeviceMismatch    Status = "device_mismatch"
	StatusFeatureDenied     Status = "feature_denied"
	StatusRevoked           Status = "revoked"
	StatusRevocationMissing Status = "revocation_data_missing"
	StatusClockRolledBack   Status = "clock_rolled_back"
	StatusInvalid           Status = "invalid"
)

// Request is the single check interface reused by applications.
type Request struct {
	Token      Token
	DeviceID   string
	Feature    string
	AppVersion string
	Now        time.Time
	// SkipRevocation must be set deliberately; when false (the default) a
	// missing/stale revocation list yields StatusRevocationMissing instead of
	// pretending revocation was checked.
	SkipRevocation bool
	// PersistClock records the observation used for rollback detection.
	PersistClock bool
}

// Result reports authorization and explicitly states whether revocation was
// actually checked against a current, signed snapshot.
type Result struct {
	Status            Status
	License           *License
	CheckedAt         time.Time
	RevocationChecked bool
	Err               error
}

// Granted is true only when every gate, including revocation, has passed.
func (r Result) Granted() bool { return r.Status == StatusGranted }

// Checker performs offline verification with a trusted keyring and an
// optional on-disk revocation snapshot.
type Checker struct {
	keyring        *Keyring
	stateDir       string
	revocationPath string
}

func NewChecker(keyring *Keyring, stateDir string) *Checker {
	return &Checker{
		keyring:        keyring,
		stateDir:       stateDir,
		revocationPath: filepath.Join(stateDir, "revocation.json"),
	}
}

// WithRevocationFile overrides the default revocation snapshot location.
func (c *Checker) WithRevocationFile(path string) *Checker {
	c.revocationPath = path
	return c
}

// Check authenticates and evaluates a license entirely offline.
func (c *Checker) Check(req Request) Result {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	res := Result{CheckedAt: now.UTC()}

	effective, err := effectiveTime(filepath.Join(c.stateDir, "clock.json"), now, req.PersistClock)
	if err != nil {
		res.Status = StatusClockRolledBack
		res.Err = err
		return res
	}
	res.CheckedAt = effective

	l, err := req.Token.parse(c.keyring)
	if err != nil {
		res.Status = StatusInvalid
		res.Err = err
		return res
	}
	res.License = l

	if !req.SkipRevocation {
		rs, rerr := loadRevocation(c.revocationPath, c.keyring)
		if rerr != nil || !rs.freshAt(effective) {
			res.Status = StatusRevocationMissing
			if rerr != nil {
				res.Err = rerr
			} else {
				res.Err = ErrRevocationMissing
			}
			return res
		}
		res.RevocationChecked = true
		if rs.serials[l.Serial] {
			res.Status = StatusRevoked
			res.Err = ErrRevoked
			return res
		}
	}

	if effective.Before(l.NotBefore) {
		res.Status = StatusNotYetValid
		res.Err = ErrNotYetValid
		return res
	}
	if !effective.Before(l.NotAfter) {
		res.Status = StatusExpired
		res.Err = ErrExpired
		return res
	}
	if req.DeviceID != l.DeviceID {
		res.Status = StatusDeviceMismatch
		res.Err = ErrDeviceMismatch
		return res
	}
	if req.Feature != "" && !l.featureAllowed(req.Feature, req.AppVersion) {
		res.Status = StatusFeatureDenied
		return res
	}
	res.Status = StatusGranted
	return res
}

// Import stores an already-authenticated token so later application launches
// use the same Check interface by serial.
func (c *Checker) Import(tok Token) (string, error) {
	l, err := tok.parse(c.keyring)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(c.stateDir, "licenses"), 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(c.stateDir, "licenses", l.Serial+".lic")
	return l.Serial, os.WriteFile(path, []byte(tok), 0o600)
}

// LoadImported reads a previously imported license token by serial.
func (c *Checker) LoadImported(serial string) (Token, error) {
	data, err := os.ReadFile(filepath.Join(c.stateDir, "licenses", serial+".lic"))
	if err != nil {
		return "", err
	}
	return Token(data), nil
}
