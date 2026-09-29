package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// IssuerPublic identifies one trusted verification key. Old keys are retained
// when the issuer rotates, which keeps previously issued licenses verifiable
// for the remainder of their validity window.
type IssuerPublic struct {
	IssuerID string `json:"issuer_id"`
	KeyID    string `json:"key_id"`
	Key      []byte `json:"key"`
}

// IssuerSecret is a temporary signing key generated for this project. Nothing
// here is shared with, or fetched from, any commercial licensing service.
type IssuerSecret struct {
	IssuerPublic
	Secret []byte `json:"secret"`
}

// NewIssuerKey generates a fresh temporary Ed25519 key for the issuer.
func NewIssuerKey(issuerID, keyID string) (*IssuerSecret, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &IssuerSecret{
		IssuerPublic: IssuerPublic{IssuerID: issuerID, KeyID: keyID, Key: pub},
		Secret:       priv,
	}, nil
}

// KeyRing holds every trusted verification key for one or more issuers.
type KeyRing struct {
	mu   sync.RWMutex
	keys map[string]IssuerPublic
}

func keyIndex(issuerID, keyID string) string {
	return issuerID + "/" + keyID
}

// NewKeyRing builds a ring from trusted issuer public keys.
func NewKeyRing(pubs ...IssuerPublic) *KeyRing {
	kr := &KeyRing{keys: map[string]IssuerPublic{}}
	for _, p := range pubs {
		kr.Add(p)
	}
	return kr
}

// Add registers (or replaces) one trusted key. Rotation adds the new key
// while leaving prior keys in place.
func (kr *KeyRing) Add(p IssuerPublic) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.keys[keyIndex(p.IssuerID, p.KeyID)] = p
}

// RotateForIssuer removes all prior keys for issuerID and installs pub.
// Licenses signed by removed keys then fail with ErrUnknownIssuerKey.
func (kr *KeyRing) RotateForIssuer(pub IssuerPublic) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	prefix := pub.IssuerID + "/"
	for k := range kr.keys {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(kr.keys, k)
		}
	}
	kr.keys[keyIndex(pub.IssuerID, pub.KeyID)] = pub
}

func (kr *KeyRing) lookup(issuerID, keyID string) (IssuerPublic, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	p, ok := kr.keys[keyIndex(issuerID, keyID)]
	return p, ok
}

// Signer issues licenses with one temporary key.
type Signer struct {
	key *IssuerSecret
}

func NewSigner(key *IssuerSecret) *Signer { return &Signer{key: key} }

// Issue signs a license and returns the importable envelope.
func (s *Signer) Issue(l License) (*Envelope, error) {
	if l.Version == 0 {
		l.Version = CurrentFormatVersion
	}
	if l.Version != CurrentFormatVersion {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedVersion, l.Version)
	}
	l.IssuerID = s.key.IssuerID
	l.KeyID = s.key.KeyID
	body, err := signingBytes(&l)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(s.key.Secret), body)
	return &Envelope{License: l, Signature: sig}, nil
}

// SaveSecret / LoadSecret persist the temporary issuer key locally.
func SaveSecret(path string, k *IssuerSecret) error {
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func LoadSecret(path string) (*IssuerSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k IssuerSecret
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

// SaveKeyRing / LoadKeyRing persist trusted public keys.
func SaveKeyRing(path string, kr *KeyRing) error {
	kr.mu.RLock()
	pubs := make([]IssuerPublic, 0, len(kr.keys))
	for _, p := range kr.keys {
		pubs = append(pubs, p)
	}
	kr.mu.RUnlock()
	data, err := json.MarshalIndent(pubs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadKeyRing(path string) (*KeyRing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pubs []IssuerPublic
	if err := json.Unmarshal(data, &pubs); err != nil {
		return nil, err
	}
	return NewKeyRing(pubs...), nil
}
