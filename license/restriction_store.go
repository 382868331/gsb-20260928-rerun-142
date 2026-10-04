package license

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type issuerRestrictionState struct {
	Serial int64                       `json:"serial"`
	Latest *SignedRestrictionUpdate    `json:"latest,omitempty"`
	Events map[string]RestrictionEvent `json:"events"`
}

// RestrictionStore persists the newest confirmed signed restriction facts
// per issuer. During an offline gap checkers keep using this snapshot
// instead of interpreting absence as "no restrictions".
type RestrictionStore struct {
	mu     sync.Mutex
	path   string
	states map[string]*issuerRestrictionState
}

func LoadRestrictionStore(path string) (*RestrictionStore, error) {
	s := &RestrictionStore{path: path, states: map[string]*issuerRestrictionState{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	if err := json.Unmarshal(data, &s.states); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	for _, st := range s.states {
		if st.Events == nil {
			st.Events = map[string]RestrictionEvent{}
		}
	}
	return s, nil
}

func (s *RestrictionStore) Import(kr *KeyRing, update *SignedRestrictionUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if update == nil {
		return ErrMalformedRestriction
	}
	if err := update.Verify(kr); err != nil {
		return err
	}
	issuer := update.Update.IssuerID
	cur := s.states[issuer]
	if cur != nil && update.Update.Serial <= cur.Serial {
		return fmt.Errorf("%w: issuer=%s known_serial=%d incoming_serial=%d",
			ErrStaleRestrictionData, issuer, cur.Serial, update.Update.Serial)
	}
	// Updates carry cumulative facts. Deleting or changing an already
	// confirmed event ID would rewrite history, including completed
	// suspensions needed to review past usage.
	if cur != nil {
		for id, old := range cur.Events {
			incomingByID := map[string]RestrictionEvent{}
			for _, event := range update.Update.Events {
				incomingByID[event.EventID] = event
			}
			incoming, ok := incomingByID[id]
			if !ok {
				return fmt.Errorf("%w: issuer=%s dropped restriction event %q",
					ErrStaleRestrictionData, issuer, id)
			}
			if !restrictionEventEqual(old, incoming) {
				return fmt.Errorf("%w: issuer=%s changed restriction event %q",
					ErrStaleRestrictionData, issuer, id)
			}
		}
	}
	next := &issuerRestrictionState{
		Serial: update.Update.Serial,
		Latest: update,
		Events: map[string]RestrictionEvent{},
	}
	for _, event := range update.Update.Events {
		next.Events[event.EventID] = event
	}
	if err := s.writeLocked(next, issuer); err != nil {
		return err
	}
	s.states[issuer] = next
	return nil
}

func (s *RestrictionStore) writeLocked(next *issuerRestrictionState, issuer string) error {
	candidate := map[string]*issuerRestrictionState{}
	for k, v := range s.states {
		candidate[k] = v
	}
	candidate[issuer] = next
	data, err := json.MarshalIndent(candidate, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".restrictions-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("%w: %v", ErrRestrictionStore, err)
	}
	return nil
}

func (s *RestrictionStore) Serial(issuer string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.states[issuer]; st != nil {
		return st.Serial
	}
	return -1
}

func (s *RestrictionStore) UpdateForIssuer(issuer string) *SignedRestrictionUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.states[issuer]; st != nil {
		return st.Latest
	}
	return nil
}

func (s *RestrictionStore) eventsForIssuer(issuer string) []RestrictionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[issuer]
	if st == nil {
		return nil
	}
	out := make([]RestrictionEvent, 0, len(st.Events))
	for _, event := range st.Events {
		out = append(out, event)
	}
	return canonicalRestrictionEvents(out)
}
