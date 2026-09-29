package license

import (
	"encoding/json"
	"time"
)

// Version is the supported license token format version.
const Version = 1

// Claim describes one licensed feature and the app version range it covers.
// Both bounds are semantic versions; MinVersion is inclusive, MaxVersion is exclusive.
type Claim struct {
	Feature    string `json:"feature"`
	MinVersion string `json:"min_version,omitempty"`
	MaxVersion string `json:"max_version,omitempty"`
}

// License is the signed payload of an authorization token.
// Feature set, validity window and device identity are independent fields.
type License struct {
	Version   int       `json:"version"`
	Serial    string    `json:"serial"`
	Issuer    string    `json:"issuer"`
	KeyID     string    `json:"kid"`
	DeviceID  string    `json:"device_id"`
	Claims    []Claim   `json:"claims"`
	IssuedAt  time.Time `json:"issued_at"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// HasFeature reports whether the license grants the named feature, without
// taking time, device or version constraints into account.
func (l *License) HasFeature(name string) bool {
	for _, c := range l.Claims {
		if c.Feature == name {
			return true
		}
	}
	return false
}

// featureAllowed reports whether a feature covers the given semantic app version.
func (l *License) featureAllowed(name, appVersion string) bool {
	for _, c := range l.Claims {
		if c.Feature != name {
			continue
		}
		if c.MinVersion != "" && compareSemver(appVersion, c.MinVersion) < 0 {
			continue
		}
		if c.MaxVersion != "" && compareSemver(appVersion, c.MaxVersion) >= 0 {
			continue
		}
		return true
	}
	return false
}

func (l *License) encode() ([]byte, error) { return json.Marshal(l) }

func decodeLicense(raw []byte) (*License, error) {
	var l License
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, ErrMalformed
	}
	if l.Version == 0 || l.Serial == "" || l.KeyID == "" || l.NotAfter.IsZero() {
		return nil, ErrMalformed
	}
	return &l, nil
}
