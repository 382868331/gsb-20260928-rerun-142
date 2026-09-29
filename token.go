package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// Token is the offline wire/import format: base64url(payload).base64url(sig).
// It carries no certificate chain and contacts no commercial service.
type Token string

func signToken(l *License, keyID string, priv ed25519.PrivateKey) (Token, error) {
	payload, err := l.encode()
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, payload)
	return Token(b + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}

// parse verifies structure and signature against the keyring, then returns
// the authenticated license. Any byte change fails signature verification.
func (t Token) parse(kr *Keyring) (*License, error) {
	parts := strings.Split(string(t), ".")
	if len(parts) != 2 {
		return nil, ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	l, err := decodeLicense(payload)
	if err != nil {
		return nil, err
	}
	if l.Version != Version {
		return nil, fmt.Errorf("%w: got v%d, want v%d", ErrVersionChange, l.Version, Version)
	}
	k, err := kr.Lookup(l.KeyID)
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.PublicKey, payload, sig) {
		return nil, ErrBadSignature
	}
	return l, nil
}

func (t Token) String() string { return string(t) }
