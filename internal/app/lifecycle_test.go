package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestRecoveryCreateGapRetainsDurableOwnership(t *testing.T) {
	dir := t.TempDir()
	o, e := state.Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := state.Record{RunID: "bakabel_gap_0123456789abcdef", DaemonID: "daemon", WorkerName: "helper-gap", Phase: state.PhaseIntent, Status: state.StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.SourceContainerID = "0123456789abcdef"
	r.SourceStartedAt = "2026-10-25T00:00:00Z"
	r.Phase = state.PhaseCreatingExec
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	o.Close()
	o, e = state.Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	c, _ := docker.NewClient(filepath.Join(dir, "disconnected.sock"))
	_, e = legacyRecover(context.Background(), o, c, func(context.Context, string) (bool, error) { return true, nil }, state.OutcomeCanceled)
	if !errors.Is(e, docker.ErrQuarantine) {
		t.Fatalf("create gap recovered: %v", e)
	}
	got, e := o.Load()
	if e != nil || got.Status != state.StatusBlocked || got.Phase != state.PhaseQuarantine {
		t.Fatalf("not durable quarantine: %+v %v", got, e)
	}
	if !errors.Is(o.NewRun(state.Record{RunID: r.RunID, DaemonID: r.DaemonID, WorkerName: r.WorkerName, Phase: state.PhaseIntent, Status: state.StatusActive}), state.ErrOwned) {
		t.Fatal("quarantine replaced")
	}
}
