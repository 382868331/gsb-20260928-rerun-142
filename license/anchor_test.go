package license

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileAnchorMonotonic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "anchor")
	a := NewFileAnchor(path)
	old, err := a.Last()
	if err != nil || !old.IsZero() {
		t.Fatalf("missing anchor should read zero, got %v %v", old, err)
	}
	t1 := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	if err := a.Advance(t1); err != nil {
		t.Fatal(err)
	}
	// An older time must never overwrite the anchor.
	if err := a.Advance(t1.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := a.Last()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(t1) {
		t.Fatalf("anchor moved backwards: %v", got)
	}
	if err := a.Advance(t2); err != nil {
		t.Fatal(err)
	}
	got, _ = a.Last()
	if !got.Equal(t2) {
		t.Fatalf("anchor did not advance: %v", got)
	}
}
