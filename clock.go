package license

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// ClockTolerance is the explicit rollback rule: clocks may move backwards by
// at most this much. Effective evaluation time never moves backwards, so a
// rollback can never extend a license's usable lifetime.
const ClockTolerance = 5 * time.Minute

type clockState struct {
	LastSeen time.Time `json:"last_seen"`
}

// effectiveTime applies the rollback rule:
//   - backwards movement <= ClockTolerance: clamp to the largest time ever
//     observed (license validity is never prolonged by the rollback);
//   - backwards movement > ClockTolerance: fail closed with ErrClockRolledBack.
func effectiveTime(path string, now time.Time, persist bool) (time.Time, error) {
	now = now.UTC()
	var st clockState
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			return time.Time{}, err
		}
	}
	effective := now
	if !st.LastSeen.IsZero() {
		if now.Add(ClockTolerance).Before(st.LastSeen) {
			return time.Time{}, ErrClockRolledBack
		}
		if st.LastSeen.After(effective) {
			effective = st.LastSeen
		}
	}
	if persist && (st.LastSeen.IsZero() || effective.After(st.LastSeen)) {
		st.LastSeen = effective
		data, _ := json.MarshalIndent(st, "", "  ")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return time.Time{}, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return time.Time{}, err
		}
	}
	return effective, nil
}
