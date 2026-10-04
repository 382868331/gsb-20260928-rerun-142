package license

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// issuerSuspensionState is the locally confirmed, newest suspension data
// for one issuer. Records are cumulative across updates, so the newest
// list alone carries the full restriction basis.
type issuerSuspensionState struct {
	Serial int64                 `json:"serial"`
	Latest *SignedSuspensionList `json:"latest"`
}

// SuspensionStore persists the newest signed suspension list per issuer.
// It is the offline recipient's retained restriction basis: while offline
// it keeps using the last confirmed list, imports are strictly monotonic
// in Serial, and the file is replaced atomically so an interrupted update
// leaves the previously trusted basis untouched.
type SuspensionStore struct {
	mu     sync.Mutex
	path   string
	states map[string]*issuerSuspensionState
}

// LoadSuspensionStore opens the local store. A missing file starts empty;
// corrupt data is an error rather than a silent reset.
func LoadSuspensionStore(path string) (*SuspensionStore, error) {
	s := &SuspensionStore{path: path, states: map[string]*issuerSuspensionState{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	if err := json.Unmarshal(data, &s.states); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	return s, nil
}

// Import verifies a signed list and applies it only when strictly newer
// than the confirmed state. Stale or non-cumulative data returns
// ErrStaleSuspensionData and changes nothing.
func (s *SuspensionStore) Import(kr *KeyRing, list *SignedSuspensionList) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if list == nil {
		return ErrMalformedSuspensionList
	}
	if err := list.Verify(kr); err != nil {
		return err
	}
	id := list.List.IssuerID
	cur := s.states[id]
	var previous *SuspensionList
	if cur != nil {
		previous = &cur.Latest.List
	}
	if err := validateSuspensionList(&list.List, previous); err != nil {
		return err
	}
	if cur != nil && list.List.Serial <= cur.Serial {
		return fmt.Errorf("%w: issuer=%s known_serial=%d incoming_serial=%d",
			ErrStaleSuspensionData, id, cur.Serial, list.List.Serial)
	}
	// Records are cumulative: a newer list that drops a previously
	// confirmed record would silently lift a restriction, which is a
	// rollback of the known basis and is refused.
	if cur != nil {
		known := map[string]bool{}
		for _, r := range list.List.Records {
			known[r.RecordID] = true
		}
		for _, old := range cur.Latest.List.Records {
			if !known[old.RecordID] {
				return fmt.Errorf("%w: issuer=%s dropped suspension record %q",
					ErrStaleSuspensionData, id, old.RecordID)
			}
		}
	}
	next := &issuerSuspensionState{Serial: list.List.Serial, Latest: list}
	if err := s.writeLocked(next, id); err != nil {
		return err
	}
	s.states[id] = next
	return nil
}

// writeLocked replaces the file atomically (temp file + rename).
func (s *SuspensionStore) writeLocked(next *issuerSuspensionState, issuer string) error {
	candidate := map[string]*issuerSuspensionState{}
	for k, v := range s.states {
		candidate[k] = v
	}
	candidate[issuer] = next
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".suspensions-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrSuspensionStore, err)
	}
	return nil
}

// Serial returns the newest confirmed serial for an issuer, or -1 when no
// signed suspension data is known locally.
func (s *SuspensionStore) Serial(issuer string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.states[issuer]; st != nil {
		return st.Serial
	}
	return -1
}

// Facts returns the resolved restriction facts for one license from the
// newest confirmed list. ok is false when no signed data exists for the
// issuer, i.e. the restriction basis is unknown rather than empty.
func (s *SuspensionStore) Facts(issuer, licenseID string) (facts []RestrictionFact, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[issuer]
	if st == nil {
		return nil, false
	}
	return resolveFacts(&st.Latest.List, licenseID), true
}

// Review re-states, against the newest confirmed basis, which existing
// usage records need review. Facts are resolved per issuer/license and a
// usage is flagged only when it falls inside the fact's effective
// interval, so later-effective restrictions never rewrite earlier usage.
func (s *SuspensionStore) Review(usages []UsageRecord) []UsageReviewItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	var facts []RestrictionFact
	for _, st := range s.states {
		facts = append(facts, resolveAllFacts(&st.Latest.List)...)
	}
	return ReviewUsage(usages, facts)
}
