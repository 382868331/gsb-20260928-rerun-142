package license

import (
	"time"
)

// PreviewChangeKind describes how one (feature, operation) permission of a
// license would change if the candidate suspension list were accepted.
type PreviewChangeKind string

const (
	// ChangeRevoked marks a permission the new data would newly restrict.
	ChangeRevoked PreviewChangeKind = "revoked"
	// ChangeRestored marks a permission the new data would make usable
	// again (a cancellation or an early end lifts a restriction).
	ChangeRestored PreviewChangeKind = "restored"
)

// PreviewScope names one license (optionally the delegation chain it is
// used under) plus the features and operations an administrator wants the
// preview evaluated for. Restrictions recorded against any chain ancestor
// narrow the leaf, mirroring CheckChain.
type PreviewScope struct {
	LicenseID string `json:"license_id"`
	// Chain lists the delegation chain root..leaf; empty means the
	// license stands alone.
	Chain []string `json:"chain,omitempty"`
	// Features are the license's granted features.
	Features []string `json:"features"`
	// Operations are the operations of interest per feature. The
	// feature-level pair (feature, "") is always evaluated.
	Operations []string `json:"operations,omitempty"`
}

// chainIDs returns the license ids whose restriction facts narrow this
// scope: the leaf plus every ancestor.
func (sc PreviewScope) chainIDs() []string {
	if len(sc.Chain) == 0 {
		return []string{sc.LicenseID}
	}
	return sc.Chain
}

// PermissionChange is one would-be permission delta for one scope,
// together with the restriction facts responsible for it.
type PermissionChange struct {
	Kind      PreviewChangeKind `json:"kind"`
	LicenseID string            `json:"license_id"`
	Feature   string            `json:"feature"`
	// Operation is empty for a feature-level change.
	Operation string `json:"operation,omitempty"`
	// Basis lists the resolved facts (record id, serial, interval) the
	// change relies on, so the applied basis stays inspectable.
	Basis []RestrictionFact `json:"basis"`
}

// UsageReviewChange splits the historical-usage re-statement into usages
// the new data would newly flag and usages it would no longer flag. This
// is deliberately separate from the current-permission diff: review
// changes describe past usage, never rewrite it.
type UsageReviewChange struct {
	NewlyFlagged []UsageReviewItem `json:"newly_flagged,omitempty"`
	Cleared      []UsageReviewItem `json:"cleared,omitempty"`
}

// SuspensionPreview is the read-only result of evaluating a candidate
// suspension list against the currently confirmed state. It is pure data:
// producing it never commits the update, never advances the trusted time
// anchor and never rewrites usage history. A saved preview keeps the
// serials and basis facts it was computed from, so it can be re-opened
// later and still shows its original grounds.
type SuspensionPreview struct {
	IssuerID      string `json:"issuer_id"`
	CurrentSerial int64  `json:"current_serial"`
	// IncomingSerial is -1 when no candidate list was supplied.
	IncomingSerial int64  `json:"incoming_serial"`
	GeneratedAt    string `json:"generated_at,omitempty"`
	// EvaluatedAt is the (rollback-protected) time the current-permission
	// diff was computed for; it is caller-supplied and persists nothing.
	EvaluatedAt time.Time `json:"evaluated_at"`
	// Accepted reports whether a real import of the same list would
	// succeed. When false, RejectReason explains why (invalid signature,
	// first-time late cancellation, stale or non-cumulative data, ...)
	// and the confirmed state is guaranteed to be untouched.
	Accepted     bool   `json:"accepted"`
	RejectReason string `json:"reject_reason,omitempty"`
	// RejectErr is the exact validation error, kept for programmatic
	// checks (errors.Is); it is not persisted in saved previews.
	RejectErr error `json:"-"`
	// Changes is the current-permission diff at EvaluatedAt, per scope.
	Changes []PermissionChange `json:"changes,omitempty"`
	// NewRecords are the suspension records the candidate list would add
	// to the confirmed basis: the applicable suspend / cancel-scheduled /
	// end-early grounds of this update.
	NewRecords []SuspensionRecord `json:"new_records,omitempty"`
	// UsageReview is the historical-usage review delta, kept distinct
	// from the current-permission Changes above.
	UsageReview *UsageReviewChange `json:"usage_review,omitempty"`
}

// pairKey identifies one (feature, operation) permission of a scope.
type pairKey struct {
	feature   string
	operation string
}

// restrictedPairs resolves which permission pairs of the scope are
// restricted at t under the given facts, and by which facts.
func restrictedPairs(facts []RestrictionFact, scope PreviewScope, t time.Time) map[pairKey][]RestrictionFact {
	chain := map[string]bool{}
	for _, id := range scope.chainIDs() {
		chain[id] = true
	}
	out := map[pairKey][]RestrictionFact{}
	ops := append([]string{""}, scope.Operations...)
	for _, feat := range scope.Features {
		for _, op := range ops {
			key := pairKey{feature: feat, operation: op}
			for _, f := range facts {
				if !chain[f.LicenseID] || !f.activeAt(t) {
					continue
				}
				// A feature-level pair is restricted only by facts that
				// suspend the whole feature; an operation pair by any
				// fact covering it. This mirrors FeatureAvailable and
				// OperationAvailable.
				if op == "" && len(f.Operations) != 0 {
					continue
				}
				if f.covers(feat, op) {
					out[key] = append(out[key], f)
				}
			}
		}
	}
	return out
}

// usageItemKey identifies one review item by the usage and the record
// that flags it, so old and new reviews can be diffed.
func usageItemKey(it UsageReviewItem) string {
	return it.Usage.LicenseID + "|" + it.Usage.Feature + "|" + it.Usage.Operation + "|" +
		it.Usage.Time.UTC().Format(time.RFC3339Nano) + "|" + it.Fact.RecordID
}

// Preview evaluates a candidate signed suspension list against the
// currently confirmed state WITHOUT applying it. It runs exactly the
// validation Import runs and reports the same accept/reject verdict, but
// it never writes the store, never advances any time anchor and never
// touches usage history. evalTime is the caller's rollback-protected
// evaluation time for the current-permission diff. scopes describe the
// licenses/features/operations to diff; usages, when given, produce the
// separate historical-usage review delta.
func (s *SuspensionStore) Preview(kr *KeyRing, list *SignedSuspensionList, evalTime time.Time, scopes []PreviewScope, usages []UsageRecord) *SuspensionPreview {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := &SuspensionPreview{EvaluatedAt: evalTime.UTC(), CurrentSerial: -1, IncomingSerial: -1}
	if list == nil {
		p.RejectReason = ErrMalformedSuspensionList.Error()
		p.RejectErr = ErrMalformedSuspensionList
		return p
	}
	p.IssuerID = list.List.IssuerID
	p.IncomingSerial = list.List.Serial
	p.GeneratedAt = list.List.GeneratedAt
	if st := s.states[list.List.IssuerID]; st != nil {
		p.CurrentSerial = st.Serial
	}

	if err := s.validateIncomingLocked(kr, list); err != nil {
		p.RejectReason = err.Error()
		p.RejectErr = err
		return p
	}
	p.Accepted = true

	var oldFacts, newFacts []RestrictionFact
	for id, st := range s.states {
		if id == list.List.IssuerID {
			continue
		}
		oldFacts = append(oldFacts, resolveAllFacts(&st.Latest.List)...)
		newFacts = append(newFacts, resolveAllFacts(&st.Latest.List)...)
	}
	if st := s.states[list.List.IssuerID]; st != nil {
		oldFacts = append(oldFacts, resolveAllFacts(&st.Latest.List)...)
	}
	newFacts = append(newFacts, resolveAllFacts(&list.List)...)

	// Records the candidate adds to the confirmed basis: the applicable
	// suspend / cancel-scheduled / end-early grounds of this update.
	known := map[string]bool{}
	if st := s.states[list.List.IssuerID]; st != nil {
		for _, r := range st.Latest.List.Records {
			known[r.RecordID] = true
		}
	}
	for _, r := range list.List.Records {
		if !known[r.RecordID] {
			p.NewRecords = append(p.NewRecords, r)
		}
	}

	// Current-permission diff at evalTime, per scope.
	for _, scope := range scopes {
		before := restrictedPairs(oldFacts, scope, evalTime)
		after := restrictedPairs(newFacts, scope, evalTime)
		ops := append([]string{""}, scope.Operations...)
		for _, feat := range scope.Features {
			for _, op := range ops {
				key := pairKey{feature: feat, operation: op}
				was := len(before[key]) > 0
				willBe := len(after[key]) > 0
				switch {
				case !was && willBe:
					p.Changes = append(p.Changes, PermissionChange{
						Kind: ChangeRevoked, LicenseID: scope.LicenseID,
						Feature: feat, Operation: op, Basis: after[key],
					})
				case was && !willBe:
					p.Changes = append(p.Changes, PermissionChange{
						Kind: ChangeRestored, LicenseID: scope.LicenseID,
						Feature: feat, Operation: op, Basis: before[key],
					})
				}
			}
		}
	}

	// Historical-usage review delta, reported separately from the
	// current-permission changes above.
	if usages != nil {
		oldReview := map[string]UsageReviewItem{}
		for _, it := range ReviewUsage(usages, oldFacts) {
			oldReview[usageItemKey(it)] = it
		}
		newReview := map[string]UsageReviewItem{}
		for _, it := range ReviewUsage(usages, newFacts) {
			newReview[usageItemKey(it)] = it
		}
		ur := &UsageReviewChange{}
		for k, it := range newReview {
			if _, ok := oldReview[k]; !ok {
				ur.NewlyFlagged = append(ur.NewlyFlagged, it)
			}
		}
		for k, it := range oldReview {
			if _, ok := newReview[k]; !ok {
				ur.Cleared = append(ur.Cleared, it)
			}
		}
		p.UsageReview = ur
	}
	return p
}
