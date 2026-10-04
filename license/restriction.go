package license

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

const (
	RestrictionSuspend = "suspend"
	RestrictionCancel  = "cancel"
	RestrictionEnd     = "end"
)

// RestrictionScope identifies exactly the resource/operation part of one
// authorization that an event affects. LicenseID is empty when the issuer
// wants the same scope on every descendant of a chain; when set, the event
// applies to that license and all descendants below it.
type RestrictionScope struct {
	LicenseID string   `json:"license_id,omitempty"`
	Resource  string   `json:"resource"`
	Actions   []string `json:"actions"`
}

// RestrictionEvent is an immutable fact. Suspend introduces a half-open
// interval [NotBefore, NotAfter). Cancel removes a suspension whose interval
// has not started. End closes an active suspension at EndedAt. Ending an
// event never turns it into a historical no-op: the suspended interval and
// its review consequence remain in the audit trail.
type RestrictionEvent struct {
	EventID    string           `json:"event_id"`
	Type       string           `json:"type"`
	TargetID   string           `json:"target_id,omitempty"`
	Scope      RestrictionScope `json:"scope"`
	NotBefore  time.Time        `json:"not_before"`
	NotAfter   time.Time        `json:"not_after,omitempty"`
	CanceledAt time.Time        `json:"canceled_at,omitempty"`
	EndedAt    time.Time        `json:"ended_at,omitempty"`
	Reason     string           `json:"reason,omitempty"`
}

// RestrictionUpdate is signed by the root issuer. Updates are cumulative:
// every higher serial repeats the complete confirmed event history, which
// lets an offline receiver replace a stale snapshot atomically while still
// refusing to delete known facts.
type RestrictionUpdate struct {
	IssuerID    string             `json:"issuer_id"`
	KeyID       string             `json:"key_id"`
	Serial      int64              `json:"serial"`
	GeneratedAt time.Time          `json:"generated_at"`
	Events      []RestrictionEvent `json:"events"`
}

type SignedRestrictionUpdate struct {
	Update    RestrictionUpdate `json:"update"`
	Signature []byte            `json:"signature"`
}

func SignRestrictionUpdate(k *IssuerSecret, u RestrictionUpdate) (*SignedRestrictionUpdate, error) {
	u.IssuerID = k.IssuerID
	u.KeyID = k.KeyID
	if err := validateRestrictionUpdate(&u); err != nil {
		return nil, err
	}
	body, err := json.Marshal(u)
	if err != nil {
		return nil, err
	}
	return &SignedRestrictionUpdate{
		Update:    u,
		Signature: ed25519.Sign(ed25519.PrivateKey(k.Secret), body),
	}, nil
}

func (s *SignedRestrictionUpdate) Verify(kr *KeyRing) error {
	if s == nil || len(s.Signature) == 0 {
		return ErrMalformedRestriction
	}
	if err := validateRestrictionUpdate(&s.Update); err != nil {
		return err
	}
	pub, ok := kr.lookup(s.Update.IssuerID, s.Update.KeyID)
	if !ok {
		return ErrUnknownIssuerKey
	}
	body, err := json.Marshal(s.Update)
	if err != nil {
		return ErrMalformedRestriction
	}
	if !ed25519.Verify(ed25519.PublicKey(pub.Key), body, s.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (s *SignedRestrictionUpdate) Encode() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func ParseSignedRestrictionUpdate(data []byte) (*SignedRestrictionUpdate, error) {
	var s SignedRestrictionUpdate
	if err := json.Unmarshal(data, &s); err != nil || len(s.Signature) == 0 {
		return nil, ErrMalformedRestriction
	}
	return &s, nil
}

func validateRestrictionUpdate(u *RestrictionUpdate) error {
	if u == nil || u.Serial < 0 {
		return ErrMalformedRestriction
	}
	seen := map[string]bool{}
	knowledge := map[string]*RestrictionEvent{}
	for i := range u.Events {
		e := &u.Events[i]
		if strings.TrimSpace(e.EventID) == "" ||
			(strings.TrimSpace(e.TargetID) == "" && (e.Type == RestrictionCancel || e.Type == RestrictionEnd)) {
			return ErrMalformedRestriction
		}
		if e.Type == RestrictionSuspend {
			if strings.TrimSpace(e.Scope.Resource) == "" || len(e.Scope.Actions) == 0 {
				return ErrMalformedRestriction
			}
			for _, action := range e.Scope.Actions {
				if strings.TrimSpace(action) == "" {
					return ErrMalformedRestriction
				}
			}
		}
		if seen[e.EventID] {
			return ErrMalformedRestriction
		}
		seen[e.EventID] = true
		switch e.Type {
		case RestrictionSuspend:
			if e.NotBefore.IsZero() || e.NotAfter.IsZero() || !e.NotAfter.After(e.NotBefore) ||
				!e.CanceledAt.IsZero() || !e.EndedAt.IsZero() {
				return ErrMalformedRestriction
			}
			knowledge[e.EventID] = e
		case RestrictionCancel:
			target, ok := knowledge[e.TargetID]
			if !ok || e.CanceledAt.IsZero() || !target.NotBefore.After(e.CanceledAt) ||
				e.Scope.Resource != "" || len(e.Scope.Actions) != 0 || e.Scope.LicenseID != "" {
				return ErrMalformedRestriction
			}
			knowledge[e.TargetID] = nil
		case RestrictionEnd:
			target, ok := knowledge[e.TargetID]
			if !ok || e.EndedAt.IsZero() || !e.EndedAt.After(target.NotBefore) || !e.EndedAt.Before(target.NotAfter) ||
				!e.NotBefore.IsZero() || !e.NotAfter.IsZero() || !e.CanceledAt.IsZero() ||
				e.Scope.Resource != "" || len(e.Scope.Actions) != 0 || e.Scope.LicenseID != "" {
				return ErrMalformedRestriction
			}
			closed := *target
			closed.NotAfter = e.EndedAt
			knowledge[e.TargetID] = &closed
		default:
			return ErrMalformedRestriction
		}
	}
	return nil
}

func canonicalRestrictionEvents(events []RestrictionEvent) []RestrictionEvent {
	out := append([]RestrictionEvent(nil), events...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out
}

func restrictionEventEqual(a, b RestrictionEvent) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func scopeContains(scope RestrictionScope, resource, action string) bool {
	if scope.Resource != "*" && scope.Resource != resource {
		return false
	}
	for _, allowed := range scope.Actions {
		if allowed == "*" || allowed == action {
			return true
		}
	}
	return false
}

func actionsContain(actions []string, action string) bool {
	for _, candidate := range actions {
		if candidate == "*" || candidate == action {
			return true
		}
	}
	return false
}
