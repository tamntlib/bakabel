package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveDoesNotAcquireOrReleaseLauncher(t *testing.T) {
	dir := t.TempDir()
	o, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	r := Record{RunID: "workflow", DaemonID: "daemon", WorkerName: "worker", Phase: PhaseIntent, Status: StatusActive}
	if err = o.NewRun(r); err != nil {
		t.Fatal(err)
	}
	got, err := Observe(dir)
	if err != nil || got != r {
		t.Fatalf("observe: %+v %v", got, err)
	}
	if _, err = Acquire(dir); !errors.Is(err, ErrBusy) {
		t.Fatal("observer released guard", err)
	}
	if err = os.WriteFile(filepath.Join(dir, "owner.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Observe(dir); err == nil {
		t.Fatal("corrupt observed state accepted")
	}
}

func TestAdvanceExportRequiresExactActiveSourceProof(t *testing.T) {
	o, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	r := Record{RunID: "workflow", DaemonID: "daemon", WorkerName: "worker", Phase: PhaseIntent, Status: StatusActive}
	if err = o.NewRun(r); err != nil {
		t.Fatal(err)
	}
	r.WorkerContainerID = "workerID"
	r.WorkerStartAuthorized = true
	r.TargetID = "target-hash"
	r.SourceContainerID = "source1"
	r.SourceStartedAt = "2026-10-25T00:00:00Z"
	r.Phase = PhaseCreatingExec
	if err = o.Save(r); err != nil {
		t.Fatal(err)
	}
	r.ExecID = "exec1"
	r.Phase = PhaseExecCreated
	if err = o.Save(r); err != nil {
		t.Fatal(err)
	}
	r.Phase = PhaseExecStarted
	if err = o.Save(r); err != nil {
		t.Fatal(err)
	}
	if _, err = o.AdvanceExport(r, TerminalProof{}); err == nil {
		t.Fatal("no source proof accepted")
	}
	wrong := r
	wrong.ExecID = "other"
	if _, err = o.AdvanceExport(wrong, TerminalProof{SourceTerminal: true}); err == nil {
		t.Fatal("stale proof accepted")
	}
	next, err := o.AdvanceExport(r, TerminalProof{SourceTerminal: true})
	if err != nil {
		t.Fatal(err)
	}
	if next.RunID != r.RunID || next.WorkerContainerID != r.WorkerContainerID || !next.WorkerStartAuthorized || next.Phase != PhaseIntent || next.ExecID != "" || next.SourceContainerID != "" || next.SourceStartedAt != "" || next.TargetID != "" {
		t.Fatalf("lost workflow identity: %+v", next)
	}
	if _, err = o.Load(); err != nil {
		t.Fatal(err)
	}
	if err = o.NewRun(Record{RunID: "different", DaemonID: "daemon", WorkerName: "worker2", Phase: PhaseIntent, Status: StatusActive}); !errors.Is(err, ErrOwned) {
		t.Fatal("advance released ownership", err)
	}
	next.Phase = PhaseQuarantine
	next.Status = StatusBlocked
	if err = o.Save(next); err != nil {
		t.Fatal(err)
	}
	if _, err = o.AdvanceExport(next, TerminalProof{SourceTerminal: true}); err == nil {
		t.Fatal("quarantine resumed")
	}
}
