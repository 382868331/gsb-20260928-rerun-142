package license

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Clock is the single time source used during verification, so tests can use
// fictional clocks without touching the host clock.
type Clock interface {
	Now() time.Time
}

type FuncClock func() time.Time

func (f FuncClock) Now() time.Time { return f() }

// SystemClock reads the operating-system clock.
var SystemClock Clock = FuncClock(time.Now)

// Anchor implements the explicit rollback rule:
//
//	effectiveNow = max(systemNow, lastObserved)
//
// A backward wall-clock jump therefore can never move evaluation earlier and
// cannot extend a license's validity. After every evaluation the anchor is
// advanced to the effective time (including on expired checks), so a sequence
// of "expire, then roll the clock back" cannot resurrect the license later.
type Anchor struct {
	mu  sync.Mutex
	ref func() time.Time
}

// FileAnchor persists the largest time ever seen for a device across runs.
type FileAnchor struct {
	path string
}

func NewFileAnchor(path string) *FileAnchor { return &FileAnchor{path: path} }

func (a *FileAnchor) Last() (time.Time, error) {
	data, err := os.ReadFile(a.path)
	if os.IsNotExist(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
}

func (a *FileAnchor) Advance(t time.Time) error {
	cur, err := a.Last()
	if err != nil {
		return err
	}
	if !t.After(cur) {
		return nil
	}
	return os.WriteFile(a.path, []byte(t.UTC().Format(time.RFC3339Nano)), 0o600)
}

// effectiveTime applies the documented rollback rule.
func effectiveTime(now, last time.Time) time.Time {
	if last.After(now) {
		return last
	}
	return now
}
