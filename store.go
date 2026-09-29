package license

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// SaveIssuerKey writes a temporary project issuer keypair with 0600 perms.
func SaveIssuerKey(dir string, k *IssuerKey, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(issuerKeyFile{IssuerKey: *k, PrivateKey: priv}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, k.KeyID+".key.json"), data, 0o600)
}

// LoadIssuerKey loads one private signing key by key ID.
func LoadIssuerKey(dir, keyID string) (*IssuerKey, ed25519.PrivateKey, error) {
	return loadPrivateKey(dir, keyID)
}

// LoadNewestIssuerKey loads the most recently written key in a directory,
// which represents the current signing key after rotation.
func LoadNewestIssuerKey(dir string) (*IssuerKey, ed25519.PrivateKey, error) {
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
	return loadPrivateKey(dir, newest[:len(newest)-len(".key.json")])
}

// SaveKeyring writes all trusted public keys, including rotated-out keys.
func SaveKeyring(dir string, kr *Keyring) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ids := make([]string, 0, len(kr.keys))
	for id := range kr.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := make([]*IssuerKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, kr.keys[id])
	}
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "keyring.json"), data, 0o600)
}

// LoadKeyring reads trusted public verification keys.
func LoadKeyring(dir string) (*Keyring, error) { return loadKeyring(dir) }

// SaveRevocationToken writes a signed revocation snapshot.
func SaveRevocationToken(path string, tok RevocationToken) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(tok), 0o600)
}
