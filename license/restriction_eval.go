package license

import "time"

// RestrictionBasis identifies the exact signed fact set used by one check.
type RestrictionBasis struct {
	Known  bool
	Serial int64
	Active []RestrictionEvent
}

// UsageRecord is an application audit entry. BasisSerial is the newest
// restriction serial the receiver had confirmed when the usage was allowed.
type UsageRecord struct {
	RecordID    string    `json:"record_id"`
	LicenseID   string    `json:"license_id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	At          time.Time `json:"at"`
	BasisSerial int64     `json:"basis_serial"`
}

// UsageReview describes one historical use that intersects a restriction
// absent from the basis the receiver used at that time. It asks for review;
// it does not rewrite the earlier validation into a historical denial.
type UsageReview struct {
	Record      UsageRecord      `json:"record"`
	Restriction RestrictionEvent `json:"restriction"`
	NewSerial   int64            `json:"new_serial"`
}

func effectiveRestrictionIntervals(events []RestrictionEvent) []RestrictionEvent {
	suspended := map[string]RestrictionEvent{}
	canceled := map[string]bool{}
	ended := map[string]RestrictionEvent{}
	for _, event := range events {
		switch event.Type {
		case RestrictionSuspend:
			suspended[event.EventID] = event
		case RestrictionCancel:
			if event.CanceledAt.Before(suspended[event.TargetID].NotBefore) {
				canceled[event.TargetID] = true
			}
		case RestrictionEnd:
			ended[event.TargetID] = event
		}
	}
	var out []RestrictionEvent
	for id, suspend := range suspended {
		if canceled[id] {
			continue
		}
		if _, ok := ended[id]; ok {
			end := ended[id]
			suspend.NotAfter = end.EndedAt
		}
		out = append(out, suspend)
	}
	return canonicalRestrictionEvents(out)
}

func restrictionAppliesToChain(event RestrictionEvent, chain []*Envelope) bool {
	for _, env := range chain {
		if event.Scope.LicenseID == "" || event.Scope.LicenseID == env.License.LicenseID {
			return true
		}
	}
	return false
}

func chainLicenseIndex(chain []*Envelope, licenseID string) int {
	for i, env := range chain {
		if env.License.LicenseID == licenseID {
			return i
		}
	}
	return -1
}

func restrictionAppliesFromDepth(event RestrictionEvent, chain []*Envelope, recordLicenseID string) bool {
	depth := chainLicenseIndex(chain, recordLicenseID)
	if depth < 0 {
		return false
	}
	if event.Scope.LicenseID == "" {
		return true
	}
	targetDepth := chainLicenseIndex(chain, event.Scope.LicenseID)
	return targetDepth >= 0 && targetDepth <= depth
}

func restrictionActiveAt(event RestrictionEvent, at time.Time) bool {
	return !at.Before(event.NotBefore) && at.Before(event.NotAfter)
}

func restrictionCovers(event RestrictionEvent, resource, action string) bool {
	return scopeContains(event.Scope, resource, action)
}

func activeRestrictions(events []RestrictionEvent, chain []*Envelope, at time.Time, resource, action string) []RestrictionEvent {
	var active []RestrictionEvent
	for _, event := range effectiveRestrictionIntervals(events) {
		if restrictionAppliesToChain(event, chain) &&
			restrictionActiveAt(event, at) && restrictionCovers(event, resource, action) {
			active = append(active, event)
		}
	}
	return active
}

func activeRestrictionsForLicense(events []RestrictionEvent, chain []*Envelope, at time.Time) []RestrictionEvent {
	var active []RestrictionEvent
	for _, event := range effectiveRestrictionIntervals(events) {
		if restrictionAppliesToChain(event, chain) && restrictionActiveAt(event, at) {
			active = append(active, event)
		}
	}
	return active
}

func availableGrants(grants []Grant, active []RestrictionEvent) []Grant {
	var out []Grant
	for _, grant := range grants {
		var actions []string
		for _, action := range grant.Actions {
			blocked := false
			for _, restriction := range active {
				if restrictionCovers(restriction, grant.Resource, action) {
					blocked = true
					break
				}
			}
			if !blocked {
				actions = append(actions, action)
			}
		}
		if len(actions) > 0 {
			out = append(out, Grant{Resource: grant.Resource, Actions: actions})
		}
	}
	return out
}

func (r *Result) HasGrant(resource, action string) bool {
	for _, grant := range r.AvailableGrants {
		if (grant.Resource == "*" || grant.Resource == resource) && actionsContain(grant.Actions, action) {
			return true
		}
	}
	return false
}

// ReviewUsage reports historical records needing a fresh human/system review
// after newer facts arrive. The old decision is preserved as an old-basis
// decision; this method does not mutate it into a past denial.
func (s *RestrictionStore) ReviewUsage(chain []*Envelope, records []UsageRecord) []UsageReview {
	if s == nil || len(chain) == 0 {
		return nil
	}
	issuer := chain[0].License.IssuerID
	s.mu.Lock()
	st := s.states[issuer]
	s.mu.Unlock()
	if st == nil {
		return nil
	}
	intervals := effectiveRestrictionIntervals(s.eventsForIssuer(issuer))
	var findings []UsageReview
	for _, record := range records {
		if record.BasisSerial >= st.Serial {
			continue
		}
		for _, event := range intervals {
			if restrictionAppliesFromDepth(event, chain, record.LicenseID) &&
				restrictionCovers(event, record.Resource, record.Action) &&
				restrictionActiveAt(event, record.At) {
				findings = append(findings, UsageReview{Record: record, Restriction: event, NewSerial: st.Serial})
			}
		}
	}
	return findings
}
