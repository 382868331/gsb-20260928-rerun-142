package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IssuerKey is a project-generated Ed25519 keypair. The private key never
// leaves the issuing side; verification only needs PublicKey.
type IssuerKey struct {
	Issuer    string `json:"issuer"`
	KeyID     string `json:"kid"`
	PublicKey []byte `json:"public_key"`
}

type issuerKeyFile struct {
	IssuerKey
	PrivateKey []byte `json:"private_key"`
}

// GenerateIssuerKey creates a fresh temporary Ed25519 key. Key rotation simply
// means generating a new key with a new KeyID while keeping the old public key
// in the verifier keyring.
func GenerateIssuerKey(issuer string) (*IssuerKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(pub)
	k := &IssuerKey{
		Issuer:    issuer,
		KeyID:     "k_" + base64.RawURLEncoding.EncodeToString(h[:8]),
		PublicKey: pub,
	}
	return k, priv, nil
}

func saveIssuerKey(dir string, k *IssuerKey, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(issuerKeyFile{IssuerKey: *k, PrivateKey: priv}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, k.KeyID+".key.json")
	return os.WriteFile(path, data, 0o600)
}

func loadPrivateKey(dir, keyID string) (*IssuerKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(dir, keyID+".key.json"))
	if err != nil {
		return nil, nil, err
	}
	var f issuerKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, err
	}
	if len(f.PrivateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: bad private key", ErrMalformed)
	}
	return &f.IssuerKey, ed25519.PrivateKey(f.PrivateKey), nil
}

func loadNewestPrivateKey(dir string) (*IssuerKey, ed25519.PrivateKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var newest string
	var newestTime int64 = -1
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().UnixNano() > newestTime {
			newestTime = info.ModTime().UnixNano()
			newest = e.Name()
		}
	}
	if newest == "" {
		return nil, nil, fmt.Errorf("no issuer keys in %s", dir)
	}
	return loadPrivateKey(dir, strings.TrimSuffix(newest, ".key.json"))
}

// Keyring holds trusted public keys, including rotated-out keys, so licenses
// signed before a rotation remain verifiable until they expire.
type Keyring struct {
	keys map[string]*IssuerKey
}

func NewKeyring(keys ...*IssuerKey) *Keyring {
	kr := &Keyring{keys: map[string]*IssuerKey{}}
	for _, k := range keys {
		kr.Add(k)
	}
	return kr
}

func (kr *Keyring) Add(k *IssuerKey) {
	if kr.keys == nil {
		kr.keys = map[string]*IssuerKey{}
	}
	kr.keys[k.KeyID] = k
}

func (kr *Keyring) Lookup(keyID string) (*IssuerKey, error) {
	k, ok := kr.keys[keyID]
	if !ok {
		return nil, ErrUnknownIssuer
	}
	return k, nil
}

func (kr *Keyring) save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ids := make([]*IssuerKey, 0, len(kr.keys))
	for _, k := range kr.keys {
		ids = append(ids, k)
	}
	data, err := json.MarshalIndent(ids, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "keyring.json"), data, 0o600)
}

func loadKeyring(dir string) (*Keyring, error) {
	data, err := os.ReadFile(filepath.Join(dir, "keyring.json"))
	if err != nil {
		return nil, err
	}
	var keys []*IssuerKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, err
	}
	return NewKeyring(keys...), nil
}
