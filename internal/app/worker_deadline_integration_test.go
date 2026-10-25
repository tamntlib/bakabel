package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestConcreteDeadlineKillsOnlyVerifiedWorker(t *testing.T) {
	f := realFixture(t)
	l := workerLaunchFixture(t, f)
	o := newOwner(t)
	lock := token(t)
	id, e := f.c.CreateExec(f.ctx, f.id, docker.ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "-U", "postgres", "-d", "fixture", "-c", "BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90)"}, Env: []string{"PGAPPNAME=" + lock}})
	if e != nil {
		t.Fatal(e)
	}
	go f.c.StartExec(f.ctx, id, io.Discard, io.Discard)
	defer func() {
		f.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='" + lock + "'")
		f.c.WaitExec(f.ctx, id)
	}()
	until := time.Now().Add(15 * time.Second)
	for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE application_name='"+lock+"' AND mode='AccessExclusiveLock' AND granted")) != "1" {
		if time.Now().After(until) {
			t.Fatal("lock not ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
	w, e := LaunchPostgresWorker(f.ctx, o, f.c, f.p, l)
	if e != nil {
		t.Fatal(e)
	}
	cleanupConcreteWorker(t, f, w)
	until = time.Now().Add(15 * time.Second)
	for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='"+w.RunID+"' AND wait_event_type='Lock'")) != "1" {
		if time.Now().After(until) {
			t.Fatal("dump not waiting")
		}
		time.Sleep(50 * time.Millisecond)
	}
	pids := workerPIDs(t, f, w)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, proof, e := FinishWorker(ctx, o, f.c, l.JobDir)
	if e == nil || !proof.NoProcesses || !proof.NoSessions || proof.ExecExitCode == nil {
		t.Fatal("deadline did not prove source terminal", proof, e)
	}
	if elapsed := time.Since(start); elapsed > 23*time.Second {
		t.Fatal("unbounded cleanup", elapsed)
	}
	terminal, e := f.c.InspectWorker(f.ctx, w)
	if e != nil || !terminal.Terminal || terminal.ExitCode != 137 {
		t.Fatal("deadline worker proof", terminal, e)
	}
	assertWorkerPIDsGone(t, pids)
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("proven terminal ownership retained", e)
	}
	v, e := f.c.InspectContainer(f.ctx, f.id)
	if e != nil || !v.State.Running || v.State.StartedAt != f.p.Source.StartedAt || v.RestartCount != 0 {
		t.Fatal("source lifecycle affected", v.State, e)
	}
	t.Logf("deadline elapsed=%s exact_worker_exit=137 source_exit=%d no_processes=true no_sessions=true source_restarts=0", time.Since(start), *proof.ExecExitCode)
}
