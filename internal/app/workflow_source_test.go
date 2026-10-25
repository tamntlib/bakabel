package app

import (
	"errors"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
	"testing"
)

func TestFailedSourceIdentityVerificationQuarantinesDespiteTerminalExec(t *testing.T) {
	o, e := state.Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := state.Record{RunID: "run", DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "wid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.SourceContainerID = "source"
	r.SourceStartedAt = "2026-01-01T00:00:00Z"
	r.Phase = state.PhaseCreatingExec
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.ExecID = "exec"
	r.Phase = state.PhaseExecCreated
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.Phase = state.PhaseExecStarted
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	zero := 0
	if e = advanceDumpCheckpoint(o, docker.TerminalProof{ExecExitCode: &zero, NoProcesses: true, NoSessions: true}, true); !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal(e)
	}
	got, e := o.Load()
	if e != nil || got.Phase != state.PhaseQuarantine || got.ExecID != "exec" || got.SourceContainerID != "source" {
		t.Fatal(got, e)
	}
}
