package license

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// issuerRevocationState is the locally known, newest state for one issuer.
// RevokedIDs is the union carried by the newest list: because each signed
// update is required to be cumulative, local state needs no history.
type issuerRevocationState struct {
	Serial     int64                 `json:"serial"`
	RevokedIDs []string              `json:"revoked_ids"`
	Latest     *SignedRevocationList `json:"latest,omitempty"`
}

// RevocationStore persists the newest signed revocation data per issuer.
// Import is all-or-nothing and the file is replaced atomically, so an
// interrupted update keeps the previously trusted state. A store using an
// older serial than the on-disk state (for example after restoring an old
// backup) cannot roll that state back.
type RevocationStore struct {
	mu     sync.Mutex
	path   string
	states map[string]*issuerRevocationState
}

// LoadRevocationStore opens the local store. A missing file starts empty;
// present-but-unreadable or internally inconsistent data is an error rather
// than a silent reset, preserving the trust boundary across restarts.
func LoadRevocationStore(path string) (*RevocationStore, error) {
	s := &RevocationStore{path: path, states: map[string]*issuerRevocationState{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	if err := json.Unmarshal(data, &s.states); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	return s, nil
}

// Import verifies a signed list and applies it only when strictly newer than
// the known state for that issuer. Stale data returns ErrStaleRevocationData
// and changes nothing; bad signatures never enter the store.
func (s *RevocationStore) Import(kr *KeyRing, list *SignedRevocationList) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if list == nil {
		return ErrMalformedRevocationList
	}
	if err := list.Verify(kr); err != nil {
		return err
	}
	id := list.List.IssuerID
	cur := s.states[id]
	if cur != nil && list.List.Serial <= cur.Serial {
		return fmt.Errorf("%w: issuer=%s known_serial=%d incoming_serial=%d",
			ErrStaleRevocationData, id, cur.Serial, list.List.Serial)
	}
	// Each update must be cumulative. A newer-serial list that silently
	// drops a previously announced id would functionally un-revoke it, so
	// treat that as a rollback of known state as well.
	if cur != nil {
		for _, known := range cur.RevokedIDs {
			if !containsID(list.List.RevokedIDs, known) {
				return fmt.Errorf("%w: issuer=%s dropped revocation for %q",
					ErrStaleRevocationData, id, known)
			}
		}
	}
	next := &issuerRevocationState{
		Serial:     list.List.Serial,
		RevokedIDs: append([]string(nil), list.List.RevokedIDs...),
		Latest:     list,
	}
	// Persist before mutating in-memory state; a crash leaves the old file.
	if err := s.writeLocked(next, id); err != nil {
		return err
	}
	s.states[id] = next
	return nil
}

// writeLocked replaces the file atomically (temp file + rename) so a crash
// or power loss mid-update cannot leave a truncated, half-trusted file.
func (s *RevocationStore) writeLocked(next *issuerRevocationState, issuer string) error {
	candidate := map[string]*issuerRevocationState{}
	for k, v := range s.states {
		candidate[k] = v
	}
	candidate[issuer] = next
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".revocations-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRevocationStore, err)
	}
	return nil
}

// Serial returns the newest applied serial for an issuer, or -1 when no
// signed data for that issuer is known locally.
func (s *RevocationStore) Serial(issuer string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.states[issuer]; st != nil {
		return st.Serial
	}
	return -1
}

// IsRevoked reports the locally known revocation status. ok is false when no
// signed data exists for the issuer, i.e. revocation was not checked.
func (s *RevocationStore) IsRevoked(issuer, licenseID string) (revoked, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[issuer]
	if st == nil {
		return false, false
	}
	return containsID(st.RevokedIDs, licenseID), true
}

// ListForIssuer returns the newest signed list applied for an issuer, if any.
func (s *RevocationStore) ListForIssuer(issuer string) *SignedRevocationList {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.states[issuer]; st != nil {
		return st.Latest
	}
	return nil
}
