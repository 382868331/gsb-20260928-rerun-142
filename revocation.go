package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"
)

// RevocationListTTL bounds how long a revocation snapshot may be treated as
// current on an offline device. An older or missing snapshot means revocation
// status is unknown, never "checked and clean".
const RevocationListTTL = 30 * 24 * time.Hour

type revocationPayload struct {
	Version     int       `json:"version"`
	KeyID       string    `json:"kid"`
	GeneratedAt time.Time `json:"generated_at"`
	Revoked     []string  `json:"revoked"`
}

// RevocationToken is a signed offline revocation snapshot.
type RevocationToken string

// SignRevocationList signs a set of revoked license serials with an issuer key.
func SignRevocationList(key *IssuerKey, priv ed25519.PrivateKey, serials []string, generatedAt time.Time) (RevocationToken, error) {
	p := revocationPayload{Version: Version, KeyID: key.KeyID, GeneratedAt: generatedAt.UTC(), Revoked: serials}
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, data)
	return RevocationToken(base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}

type revocationSet struct {
	payload *revocationPayload
	serials map[string]bool
}

func parseRevocation(tok RevocationToken, kr *Keyring) (*revocationSet, error) {
	raw := string(tok)
	dot := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, ErrMalformed
	}
	data, err := base64.RawURLEncoding.DecodeString(raw[:dot])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(raw[dot+1:])
	if err != nil {
		return nil, ErrMalformed
	}
	var p revocationPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrMalformed
	}
	k, err := kr.Lookup(p.KeyID)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.PublicKey, data, sig) {
		return nil, ErrBadSignature
	}
	set := &revocationSet{payload: &p, serials: map[string]bool{}}
	for _, s := range p.Revoked {
		set.serials[s] = true
	}
	return set, nil
}

func loadRevocation(path string, kr *Keyring) (*revocationSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrRevocationMissing
	}
	set, err := parseRevocation(RevocationToken(data), kr)
	if err != nil {
		return nil, err
	}
	return set, nil
}

func (rs *revocationSet) freshAt(now time.Time) bool {
	return now.Sub(rs.payload.GeneratedAt.UTC()) <= RevocationListTTL
}
