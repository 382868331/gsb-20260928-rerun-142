package license

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// revStoreState is the durable local revocation state. It records the highest
// signed serial ever accepted plus the union of all revoked ids seen in
// accepted lists. Persisting it means that receiving older material after a
// save/reopen cannot remove a revocation that was already known.
type revStoreState struct {
	IssuerID      string   `json:"issuer_id"`
	AppliedSerial uint64   `json:"applied_serial"`
	RevokedIDs    []string `json:"revoked_ids"`
}

// RevocationStore is the durable, monotonic offline revocation state for one
// device. All updates go through signed lists and are either fully applied
// (atomic write) or rejected; an interrupted update leaves the previous state
// intact.
type RevocationStore struct {
	path  string
	state revStoreState
	have  bool
}

// NewRevocationStore opens (lazily loading) the persistent state at path.
func NewRevocationStore(path string) *RevocationStore {
	return &RevocationStore{path: path}
}

func (s *RevocationStore) load() error {
	if s.have {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.have = true
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return ErrMalformedRevocationList
	}
	s.have = true
	return nil
}

// HasData reports whether any signed revocation material was applied yet.
// Missing data and a clean check remain distinct outcomes.
func (s *RevocationStore) HasData() bool {
	if err := s.load(); err != nil {
		return false
	}
	return s.state.AppliedSerial > 0 || len(s.state.RevokedIDs) > 0
}

// Apply validates incoming material and merges it only when it is newer than
// the applied state:
//
//   - signature must verify against the trusted ring;
//   - serial must be strictly greater than the applied serial;
//   - revoked ids are union-merged, never removed.
//
// Older/duplicate material returns ErrStaleRevocationData and changes
// nothing, including after the store is closed and reopened.
func (s *RevocationStore) Apply(kr *KeyRing, incoming *SignedRevocationList) error {
	if err := s.load(); err != nil {
		return err
	}
	if incoming == nil || len(incoming.Signature) == 0 {
		return ErrMalformedRevocationList
	}
	if s.state.IssuerID != "" && incoming.List.IssuerID != s.state.IssuerID {
		return ErrMalformedRevocationList
	}
	if err := incoming.Verify(kr); err != nil {
		return err
	}
	if incoming.List.Serial <= s.state.AppliedSerial {
		return ErrStaleRevocationData
	}

	next := revStoreState{
		IssuerID:      incoming.List.IssuerID,
		AppliedSerial: incoming.List.Serial,
		RevokedIDs:    append(append([]string(nil), s.state.RevokedIDs...), incoming.List.RevokedIDs...),
	}
	next.RevokedIDs = dedupeStrings(next.RevokedIDs)
	if err := atomicWriteJSON(s.path, next); err != nil {
		return err
	}
	s.state = next
	s.have = true
	return nil
}

// Snapshot returns the currently applied view (highest accepted serial with
// the unioned revoked set) for use by Checker. It returns nil when no
// material has been applied, preserving the missing vs checked distinction.
func (s *RevocationStore) Snapshot() *SignedRevocationList {
	if err := s.load(); err != nil || !s.HasData() {
		return nil
	}
	return &SignedRevocationList{
		List: RevocationList{
			IssuerID:   s.state.IssuerID,
			Serial:     s.state.AppliedSerial,
			RevokedIDs: append([]string(nil), s.state.RevokedIDs...),
		},
	}
}

// IsRevoked reports the durable known status of id.
func (s *RevocationStore) IsRevoked(id string) bool {
	if err := s.load(); err != nil {
		return false
	}
	return containsID(s.state.RevokedIDs, id)
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rev-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
