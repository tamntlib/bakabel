package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveResultDoesNotTakeWorkerGuardOrCreateFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := ObserveResult(dir); !errors.Is(err, ErrNoResult) {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("health mutated empty state")
	}
	o, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.NewRun(initial()); err != nil {
		t.Fatal(err)
	}
	if err = o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeSuccess, Operation: "backup"}); err != nil {
		t.Fatal(err)
	}
	got, err := ObserveResult(dir)
	if err != nil || got.Status != OutcomeSuccess || got.LastBackupSuccessAt == "" {
		t.Fatal(got, err)
	}
	if err = os.Remove(filepath.Join(dir, "last-result.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte(`{"runID":"run","status":"success"}`), 0600)
	if err = os.Symlink(outside, filepath.Join(dir, "last-result.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = ObserveResult(dir); err == nil {
		t.Fatal("followed result symlink")
	}
}
