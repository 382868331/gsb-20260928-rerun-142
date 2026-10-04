package license

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"
)

// SuspensionKind distinguishes the three record types. Cancelling a
// suspension that has not started yet and ending one that is already in
// effect are deliberately DIFFERENT records: the first erases a future
// interval, the second truncates a live one.
type SuspensionKind string

const (
	// Suspend restricts features/operations of one license for [NotBefore, NotAfter].
	Suspend SuspensionKind = "suspend"
	// CancelScheduled removes a suspension whose NotBefore is still in the
	// future at the time the list is generated. It never rewrites the past.
	CancelScheduled SuspensionKind = "cancel-scheduled"
	// EndEarly truncates a suspension that has already started: the
	// effective interval becomes [NotBefore, EndedAt].
	EndEarly SuspensionKind = "end-early"
)

// SuspensionRecord restricts named resources (Features) and operations of
// one license for a bounded interval. An empty Features or Operations list
// means "all of them". The license itself stays valid; only the listed
// scope is temporarily unusable.
type SuspensionRecord struct {
	RecordID   string         `json:"record_id"`
	Kind       SuspensionKind `json:"kind"`
	LicenseID  string         `json:"license_id"`
	Features   []string       `json:"features,omitempty"`
	Operations []string       `json:"operations,omitempty"`
	NotBefore  string         `json:"not_before,omitempty"`
	NotAfter   string         `json:"not_after,omitempty"`
	// TargetRecordID is set by cancel-scheduled / end-early records and
	// references the suspend record they act on.
	TargetRecordID string `json:"target_record_id,omitempty"`
	// EndedAt is set by end-early records: the new, earlier end of the
	// target suspension interval.
	EndedAt string `json:"ended_at,omitempty"`
}

// SuspensionList is the issuer-signed, cumulative set of suspension
// records. Like the revocation list it carries a strictly increasing
// Serial; offline recipients keep the newest confirmed list as their
// restriction basis and never roll it backwards.
type SuspensionList struct {
	IssuerID    string             `json:"issuer_id"`
	KeyID       string             `json:"key_id"`
	Serial      int64              `json:"serial"`
	GeneratedAt string             `json:"generated_at"`
	Records     []SuspensionRecord `json:"records"`
}

// SignedSuspensionList pairs the list with its issuer signature.
type SignedSuspensionList struct {
	List      SuspensionList `json:"list"`
	Signature []byte         `json:"signature"`
}

func (s *SignedSuspensionList) Encode() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// SignSuspensionList signs a suspension list with an issuer key.
func SignSuspensionList(k *IssuerSecret, sl SuspensionList) (*SignedSuspensionList, error) {
	sl.IssuerID = k.IssuerID
	sl.KeyID = k.KeyID
	body, err := json.Marshal(sl)
	if err != nil {
		return nil, err
	}
	return &SignedSuspensionList{
		List:      sl,
		Signature: ed25519.Sign(ed25519.PrivateKey(k.Secret), body),
	}, nil
}

// Verify checks the signature against the ring.
func (s *SignedSuspensionList) Verify(kr *KeyRing) error {
	if s == nil || len(s.Signature) == 0 {
		return ErrMalformedSuspensionList
	}
	pub, ok := kr.lookup(s.List.IssuerID, s.List.KeyID)
	if !ok {
		return ErrUnknownIssuerKey
	}
	body, err := json.Marshal(s.List)
	if err != nil {
		return ErrMalformedSuspensionList
	}
	if !ed25519.Verify(ed25519.PublicKey(pub.Key), body, s.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

// validateSuspensionList enforces structural and kind rules. The list's
// GeneratedAt is the decision instant: cancel-scheduled is only legal for
// suspensions that have not started yet, end-early only for ones that
// have. Mixing them up is rejected instead of silently reinterpreted.
func validateSuspensionList(l *SuspensionList) error {
	gen, err := time.Parse(time.RFC3339, l.GeneratedAt)
	if err != nil {
		return fmt.Errorf("%w: bad generated_at", ErrMalformedSuspensionList)
	}
	seen := map[string]bool{}
	suspends := map[string]SuspensionRecord{}
	for _, r := range l.Records {
		if r.RecordID == "" || seen[r.RecordID] {
			return fmt.Errorf("%w: duplicate or empty record id", ErrInvalidSuspensionRecord)
		}
		seen[r.RecordID] = true
		if r.Kind == Suspend {
			suspends[r.RecordID] = r
		}
	}
	for _, r := range l.Records {
		switch r.Kind {
		case Suspend:
			if r.LicenseID == "" {
				return fmt.Errorf("%w: suspend %q misses license id", ErrInvalidSuspensionRecord, r.RecordID)
			}
			nbf, err1 := time.Parse(time.RFC3339, r.NotBefore)
			nbt, err2 := time.Parse(time.RFC3339, r.NotAfter)
			if err1 != nil || err2 != nil || nbt.Before(nbf) {
				return fmt.Errorf("%w: suspend %q has a bad interval", ErrInvalidSuspensionRecord, r.RecordID)
			}
		case CancelScheduled:
			tgt, ok := suspends[r.TargetRecordID]
			if !ok {
				return fmt.Errorf("%w: cancel %q targets unknown record", ErrInvalidSuspensionRecord, r.RecordID)
			}
			nbf, _ := time.Parse(time.RFC3339, tgt.NotBefore)
			if !nbf.After(gen) {
				return fmt.Errorf("%w: cancel %q targets a suspension that already started; use end-early",
					ErrInvalidSuspensionRecord, r.RecordID)
			}
		case EndEarly:
			tgt, ok := suspends[r.TargetRecordID]
			if !ok {
				return fmt.Errorf("%w: end %q targets unknown record", ErrInvalidSuspensionRecord, r.RecordID)
			}
			nbf, _ := time.Parse(time.RFC3339, tgt.NotBefore)
			nbt, _ := time.Parse(time.RFC3339, tgt.NotAfter)
			ended, err := time.Parse(time.RFC3339, r.EndedAt)
			if err != nil {
				return fmt.Errorf("%w: end %q has a bad ended_at", ErrInvalidSuspensionRecord, r.RecordID)
			}
			if nbf.After(gen) {
				return fmt.Errorf("%w: end %q targets a suspension that has not started; use cancel-scheduled",
					ErrInvalidSuspensionRecord, r.RecordID)
			}
			if !ended.After(nbf) || ended.After(nbt) {
				return fmt.Errorf("%w: end %q sets ended_at outside the target interval",
					ErrInvalidSuspensionRecord, r.RecordID)
			}
		default:
			return fmt.Errorf("%w: unknown kind %q", ErrInvalidSuspensionRecord, r.Kind)
		}
	}
	return nil
}

// RestrictionFact is one resolved, currently known restriction. Every
// verification and every usage review reports exactly the facts it relied
// on, so the applied basis is always inspectable.
type RestrictionFact struct {
	RecordID   string   `json:"record_id"`
	IssuerID   string   `json:"issuer_id"`
	Serial     int64    `json:"serial"`
	LicenseID  string   `json:"license_id"`
	Features   []string `json:"features,omitempty"`
	Operations []string `json:"operations,omitempty"`
	NotBefore  string   `json:"not_before"`
	// NotAfter is the EFFECTIVE end: truncated when an end-early record
	// applies. Facts never move NotBefore; restrictions are never
	// rewritten to have applied earlier than they did.
	NotAfter string `json:"not_after"`
}

// covers reports whether the fact restricts (feature, operation).
func (f RestrictionFact) covers(feature, operation string) bool {
	return (len(f.Features) == 0 || containsID(f.Features, feature)) &&
		(len(f.Operations) == 0 || containsID(f.Operations, operation))
}

// activeAt reports whether the fact's interval contains t.
func (f RestrictionFact) activeAt(t time.Time) bool {
	nbf, err1 := time.Parse(time.RFC3339, f.NotBefore)
	nbt, err2 := time.Parse(time.RFC3339, f.NotAfter)
	if err1 != nil || err2 != nil {
		return false
	}
	return !t.Before(nbf) && !t.After(nbt)
}

// resolveFacts applies cancel-scheduled and end-early records to the
// suspend records of one license and returns the resolved facts. The
// result is interval data only; callers filter by the time they evaluate.
func resolveFacts(l *SuspensionList, licenseID string) []RestrictionFact {
	var out []RestrictionFact
	for _, f := range resolveAllFacts(l) {
		if f.LicenseID == licenseID {
			out = append(out, f)
		}
	}
	return out
}

// resolveAllFacts resolves every suspend record in the list, regardless
// of the license it targets.
func resolveAllFacts(l *SuspensionList) []RestrictionFact {
	suspends := map[string]SuspensionRecord{}
	order := []string{}
	cancelled := map[string]bool{}
	endedAt := map[string]string{}
	for _, r := range l.Records {
		switch r.Kind {
		case Suspend:
			if _, dup := suspends[r.RecordID]; !dup {
				order = append(order, r.RecordID)
			}
			suspends[r.RecordID] = r
		case CancelScheduled:
			cancelled[r.TargetRecordID] = true
		case EndEarly:
			endedAt[r.TargetRecordID] = r.EndedAt
		}
	}
	var facts []RestrictionFact
	for _, id := range order {
		r := suspends[id]
		if cancelled[id] {
			continue
		}
		end := r.NotAfter
		if e, ok := endedAt[id]; ok && e < end {
			end = e
		}
		facts = append(facts, RestrictionFact{
			RecordID:   r.RecordID,
			IssuerID:   l.IssuerID,
			Serial:     l.Serial,
			LicenseID:  r.LicenseID,
			Features:   r.Features,
			Operations: r.Operations,
			NotBefore:  r.NotBefore,
			NotAfter:   end,
		})
	}
	return facts
}

// UsageRecord is one locally logged past use of a restricted scope.
type UsageRecord struct {
	LicenseID string    `json:"license_id"`
	Feature   string    `json:"feature"`
	Operation string    `json:"operation"`
	Time      time.Time `json:"time"`
	// Chain optionally lists the delegation chain (root..leaf) the usage
	// ran under. A restriction recorded against any chain ancestor also
	// covers this usage, mirroring the narrowing rule of CheckChain.
	Chain []string `json:"chain,omitempty"`
}

// restrictedBy reports whether the fact applies to this usage
// license, directly or through a chain ancestor.
func (u UsageRecord) restrictedBy(f RestrictionFact) bool {
	if f.LicenseID == u.LicenseID {
		return true
	}
	for _, id := range u.Chain {
		if id == f.LicenseID {
			return true
		}
	}
	return false
}

// UsageReviewItem flags one past usage record together with the
// restriction fact that now covers it.
type UsageReviewItem struct {
	Usage UsageRecord     `json:"usage"`
	Fact  RestrictionFact `json:"fact"`
}

// ReviewUsage re-states, against the CURRENTLY confirmed restriction
// facts, which existing usage records need review. A usage is flagged only
// when it happened inside the fact's effective interval: a restriction
// that took effect later never reaches back and rewrites earlier usage.
func ReviewUsage(usages []UsageRecord, facts []RestrictionFact) []UsageReviewItem {
	var out []UsageReviewItem
	for _, u := range usages {
		for _, f := range facts {
			if !u.restrictedBy(f) {
				continue
			}
			if f.covers(u.Feature, u.Operation) && f.activeAt(u.Time) {
				out = append(out, UsageReviewItem{Usage: u, Fact: f})
				break
			}
		}
	}
	return out
}
