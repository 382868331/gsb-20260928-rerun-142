package license

import (
	"sort"
	"time"
)

// ChangeKind classifies one permission change shown in an update preview.
type ChangeKind string

const (
	// ChangeAdded marks a permission the update would newly grant.
	// Suspension data only ever restricts or restores, so a preview of
	// suspension updates never produces this kind; it exists so consumers
	// can rely on a closed set of change kinds.
	ChangeAdded ChangeKind = "added"
	// ChangeRevoked marks a permission a new restriction would withdraw.
	ChangeRevoked ChangeKind = "revoked"
	// ChangeRestored marks a permission a cancellation or early end
	// would hand back.
	ChangeRestored ChangeKind = "restored"
)

// BasisRecord is one suspension-list record a preview relies on, tagged
// with the serial of the list that carries it. Saved previews keep the
// full records, so an old preview can always be re-opened and its
// original basis inspected.
type BasisRecord struct {
	Serial int64 `json:"serial"`
	SuspensionRecord
}

// PermissionChange describes how one (license, feature, operation) pair
// would change at the evaluation time if the incoming data were accepted.
// Operation "" means the feature as a whole.
type PermissionChange struct {
	LicenseID string        `json:"license_id"`
	Feature   string        `json:"feature"`
	Operation string        `json:"operation,omitempty"`
	Change    ChangeKind    `json:"change"`
	Basis     []BasisRecord `json:"basis"`
}

// SuspensionPreview is the read-only result of previewing a suspension
// data update against the currently confirmed state. It commits nothing:
// the store, the trusted time anchor and every usage record are left
// exactly as they were.
type SuspensionPreview struct {
	IssuerID        string    `json:"issuer_id"`
	CurrentSerial   int64     `json:"current_serial"`
	IncomingSerial  int64     `json:"incoming_serial"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
	ClockRolledBack bool      `json:"clock_rolled_back"`
	// Accepted reports whether the incoming data would be accepted by a
	// real import. When false, RejectReason names the exact cause (bad
	// signature, stale serial, dropped record, late first-time cancel...)
	// and the confirmed state is guaranteed untouched.
	Accepted     bool   `json:"accepted"`
	RejectReason string `json:"reject_reason,omitempty"`
	// PermissionChanges are the CURRENT permission changes at EvaluatedAt,
	// per feature and operation of every license in the evaluated chain.
	PermissionChanges []PermissionChange `json:"permission_changes,omitempty"`
	// UsageReviewChanges are the HISTORICAL usage records that would
	// newly need review under the incoming basis. They re-state the past
	// against new facts; they never rewrite any usage record.
	UsageReviewChanges []UsageReviewItem `json:"usage_review_changes,omitempty"`
	// Records are the applicable suspend / cancel-scheduled / end-early
	// records of the incoming list (the restriction basis the preview
	// reasoned over).
	Records []BasisRecord `json:"records,omitempty"`
}

// Preview evaluates an incoming signed suspension list against the
// confirmed state WITHOUT applying it. It runs exactly the validation a
// real Import would run, so Accepted is true iff Import would succeed;
// either way the store is not modified, no time anchor is advanced and no
// usage record is rewritten. Evaluation uses the rollback-protected
// effective time max(now, lastAnchor), same as Check.
//
// chain (root first, leaf last) supplies the licenses whose features and
// operations are diffed; a restriction recorded against any chain
// ancestor narrows every descendant, mirroring CheckChain. usages are
// existing local usage records used to compute UsageReviewChanges.
func (s *SuspensionStore) Preview(kr *KeyRing, list *SignedSuspensionList, chain []*Envelope, usages []UsageRecord, now, lastAnchor time.Time) *SuspensionPreview {
	s.mu.Lock()
	defer s.mu.Unlock()
	eff := effectiveTime(now, lastAnchor)
	p := &SuspensionPreview{
		CurrentSerial:   -1,
		EvaluatedAt:     eff,
		ClockRolledBack: now.Before(lastAnchor),
	}
	if list == nil {
		p.RejectReason = ErrMalformedSuspensionList.Error()
		return p
	}
	p.IssuerID = list.List.IssuerID
	p.IncomingSerial = list.List.Serial
	cur := s.states[list.List.IssuerID]
	if cur != nil {
		p.CurrentSerial = cur.Serial
	}
	if err := validateIncomingSuspension(kr, cur, list); err != nil {
		p.RejectReason = err.Error()
		return p
	}
	p.Accepted = true

	var curFacts []RestrictionFact
	if cur != nil {
		curFacts = resolveAllFacts(&cur.Latest.List)
	}
	newFacts := resolveAllFacts(&list.List)

	// Applicable records: suspend records targeting any chain license,
	// plus the cancel/end records acting on them.
	suspends := map[string]SuspensionRecord{}
	recordByID := map[string]SuspensionRecord{}
	for _, r := range list.List.Records {
		recordByID[r.RecordID] = r
		if r.Kind == Suspend {
			suspends[r.RecordID] = r
		}
	}
	chainIDs := map[string]bool{}
	for _, env := range chain {
		if env != nil {
			chainIDs[env.License.LicenseID] = true
		}
	}
	for _, r := range list.List.Records {
		target := r.LicenseID
		if r.Kind != Suspend {
			if tgt, ok := suspends[r.TargetRecordID]; ok {
				target = tgt.LicenseID
			}
		}
		if chainIDs[target] {
			p.Records = append(p.Records, BasisRecord{Serial: list.List.Serial, SuspensionRecord: r})
		}
	}

	// Current permission changes, per chain license. A license at depth d
	// is narrowed by the facts of every ancestor up to and including d.
	for depth, env := range chain {
		if env == nil {
			continue
		}
		ids := map[string]bool{}
		for i := 0; i <= depth && i < len(chain); i++ {
			if chain[i] != nil {
				ids[chain[i].License.LicenseID] = true
			}
		}
		curApp := filterFacts(curFacts, ids)
		newApp := filterFacts(newFacts, ids)
		for _, feat := range env.License.Features {
			ops := map[string]bool{"": true}
			for _, f := range append(append([]RestrictionFact{}, curApp...), newApp...) {
				if len(f.Features) == 0 || containsID(f.Features, feat) {
					for _, op := range f.Operations {
						ops[op] = true
					}
				}
			}
			opList := make([]string, 0, len(ops))
			for op := range ops {
				opList = append(opList, op)
			}
			sort.Strings(opList)
			for _, op := range opList {
				before := restrictedAt(curApp, feat, op, eff)
				after := restrictedAt(newApp, feat, op, eff)
				if before == after {
					continue
				}
				ch := PermissionChange{
					LicenseID: env.License.LicenseID,
					Feature:   feat,
					Operation: op,
				}
				if after {
					ch.Change = ChangeRevoked
					ch.Basis = restrictBasis(recordByID, newApp, feat, op, eff, list.List.Serial)
				} else {
					ch.Change = ChangeRestored
					ch.Basis = restoreBasis(recordByID, curApp, feat, op, eff, list.List.Serial)
				}
				p.PermissionChanges = append(p.PermissionChanges, ch)
			}
		}
	}

	// Historical usage review changes: usages flagged by the incoming
	// basis that the confirmed basis does not already flag.
	curItems := map[string]bool{}
	for _, it := range ReviewUsage(usages, curFacts) {
		curItems[reviewKey(it)] = true
	}
	for _, it := range ReviewUsage(usages, newFacts) {
		if !curItems[reviewKey(it)] {
			p.UsageReviewChanges = append(p.UsageReviewChanges, it)
		}
	}
	return p
}

// filterFacts keeps the facts recorded against any of the given licenses.
func filterFacts(facts []RestrictionFact, ids map[string]bool) []RestrictionFact {
	var out []RestrictionFact
	for _, f := range facts {
		if ids[f.LicenseID] {
			out = append(out, f)
		}
	}
	return out
}

// restrictedAt reports whether any fact restricts (feature, operation) at t.
func restrictedAt(facts []RestrictionFact, feature, operation string, t time.Time) bool {
	for _, f := range facts {
		if f.activeAt(t) && f.covers(feature, operation) {
			return true
		}
	}
	return false
}

// restrictBasis names the incoming suspend records responsible for a
// newly restricted (feature, operation).
func restrictBasis(records map[string]SuspensionRecord, facts []RestrictionFact, feature, operation string, t time.Time, serial int64) []BasisRecord {
	var out []BasisRecord
	for _, f := range facts {
		if f.activeAt(t) && f.covers(feature, operation) {
			if r, ok := records[f.RecordID]; ok {
				out = append(out, BasisRecord{Serial: serial, SuspensionRecord: r})
			}
		}
	}
	return out
}

// restoreBasis names the cancel-scheduled / end-early records that lift a
// previously active restriction on (feature, operation).
func restoreBasis(records map[string]SuspensionRecord, curFacts []RestrictionFact, feature, operation string, t time.Time, serial int64) []BasisRecord {
	var out []BasisRecord
	for _, f := range curFacts {
		if !f.activeAt(t) || !f.covers(feature, operation) {
			continue
		}
		found := false
		for _, r := range records {
			if (r.Kind == CancelScheduled || r.Kind == EndEarly) && r.TargetRecordID == f.RecordID {
				out = append(out, BasisRecord{Serial: serial, SuspensionRecord: r})
				found = true
			}
		}
		if !found {
			if r, ok := records[f.RecordID]; ok {
				out = append(out, BasisRecord{Serial: serial, SuspensionRecord: r})
			}
		}
	}
	return out
}

// reviewKey identifies one (usage, fact) pair so the preview can report
// only newly flagged usage.
func reviewKey(it UsageReviewItem) string {
	return it.Usage.LicenseID + "|" + it.Usage.Feature + "|" + it.Usage.Operation + "|" +
		it.Usage.Time.UTC().Format(time.RFC3339Nano) + "|" + it.Fact.RecordID
}
