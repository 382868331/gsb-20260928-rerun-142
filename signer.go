package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// Signer issues offline licenses with one project-generated keypair.
type Signer struct {
	key  *IssuerKey
	priv ed25519.PrivateKey
}

func NewSigner(key *IssuerKey, priv ed25519.PrivateKey) *Signer {
	return &Signer{key: key, priv: priv}
}

// IssueOptions defines feature set, validity window and bound device.
type IssueOptions struct {
	DeviceID  string
	Claims    []Claim
	NotBefore time.Time
	NotAfter  time.Time
	IssuedAt  time.Time
}

// Issue creates a signed license. Validity is always an explicit window; the
// caller controls clock inputs so tests are deterministic.
func (s *Signer) Issue(opts IssueOptions) (Token, error) {
	if opts.DeviceID == "" {
		return "", ErrMalformed
	}
	if opts.NotAfter.IsZero() || !opts.NotBefore.Before(opts.NotAfter) {
		return "", ErrMalformed
	}
	if opts.IssuedAt.IsZero() {
		opts.IssuedAt = opts.NotBefore
	}
	var sb [16]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return "", err
	}
	id := sha256.Sum256(append(sb[:], []byte(opts.DeviceID)...))
	l := &License{
		Version:   Version,
		Serial:    "lic_" + base64.RawURLEncoding.EncodeToString(id[:16]),
		Issuer:    s.key.Issuer,
		KeyID:     s.key.KeyID,
		DeviceID:  opts.DeviceID,
		Claims:    opts.Claims,
		IssuedAt:  opts.IssuedAt.UTC(),
		NotBefore: opts.NotBefore.UTC(),
		NotAfter:  opts.NotAfter.UTC(),
	}
	return signToken(l, s.key.KeyID, s.priv)
}
