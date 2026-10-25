package state

import (
	"testing"
	"time"
)

func TestBackupHealthTimestampSurvivesFailureAndRestore(t *testing.T) {
	o, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	release := func(run, operation string, outcome Outcome) Result {
		t.Helper()
		r := initial()
		r.RunID = run
		if err := o.NewRun(r); err != nil {
			t.Fatal(err)
		}
		if err := o.Release(r, TerminalProof{WorkerTerminal: true, SourceTerminal: true}, Result{RunID: run, Status: outcome, Operation: operation}); err != nil {
			t.Fatal(err)
		}
		got, err := o.LastResult()
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	start := time.Now()
	first := release("first", "backup", OutcomeSuccess)
	at, err := time.Parse(time.RFC3339Nano, first.FinishedAt)
	if err != nil || at.Before(start) || at.After(time.Now()) || first.LastBackupSuccessAt != first.FinishedAt {
		t.Fatal(first, err)
	}
	for _, tc := range []struct {
		run, operation string
		outcome        Outcome
	}{{"failed", "backup", OutcomeFailed}, {"restored", "restore", OutcomeSuccess}, {"legacy", "", OutcomeSuccess}} {
		got := release(tc.run, tc.operation, tc.outcome)
		if got.LastBackupSuccessAt != first.LastBackupSuccessAt {
			t.Fatalf("%s changed successful backup timestamp: %+v", tc.run, got)
		}
	}
}
