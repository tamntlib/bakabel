package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func workflowFixtureLaunch(t *testing.T, f *fixture) (config.Config, RuntimeMountPlan) {
	t.Helper()
	r := repoFixture(t, f.ctx)
	var pass, repository string
	for _, env := range r.Env {
		if strings.HasPrefix(env, "RESTIC_PASSWORD_FILE=") {
			pass = strings.TrimPrefix(env, "RESTIC_PASSWORD_FILE=")
		}
		if strings.HasPrefix(env, "RESTIC_REPOSITORY=") {
			repository = strings.TrimPrefix(env, "RESTIC_REPOSITORY=")
		}
	}
	dir := t.TempDir()
	cfg := config.Config{Version: 1, Installation: "workflow-fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: repository, Credentials: config.Credentials{PasswordFile: pass}, DockerSocket: f.socket, StateDir: dir, WorkerImage: os.Getenv("BAKABEL_WORKFLOW_IMAGE_ID"), Timeout: time.Minute, Timezone: "UTC"}
	if cfg.Validate() != nil {
		t.Fatal("immutable BAKABEL_WORKFLOW_IMAGE_ID required")
	}
	plan := RuntimeMountPlan{NodeState: hostPath(dir), Repository: "/repository", Mounts: []docker.WorkerMount{{Source: hostPath(dir), Target: dir}, {Source: hostPath(repository), Target: "/repository"}, {Source: hostPath(pass), Target: workerPassword, ReadOnly: true}, {Source: f.socket, Target: workerSocket, ReadOnly: true}}}
	return cfg, plan
}

func TestWorkflowSIGKILLRetainsOwnerAndFreshRecoveryUsesFrozenDatabase(t *testing.T) {
	f := realFixture(t)
	cfg, plan := workflowFixtureLaunch(t, f)
	f.sql("CREATE DATABASE frozen_override")
	f.control("psql", "-XAt", "-U", "postgres", "-d", "frozen_override", "-c", "CREATE TABLE alternate AS SELECT generate_series(1,20000) AS id")
	lock, e := f.c.CreateExec(f.ctx, f.id, docker.ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "-U", "postgres", "-d", "frozen_override", "-c", "BEGIN; LOCK TABLE alternate IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(120)"}, Env: []string{"PGAPPNAME=workflow-lock-fixture"}})
	if e != nil {
		t.Fatal(e)
	}
	lockDone := make(chan error, 1)
	go func() { lockDone <- f.c.StartExec(f.ctx, lock, io.Discard, io.Discard) }()
	for {
		n := f.control("psql", "-XAt", "-U", "postgres", "-d", "frozen_override", "-c", "SELECT count(*) FROM pg_stat_activity WHERE application_name='workflow-lock-fixture' AND wait_event='PgSleep'")
		if strings.TrimSpace(n) == "1" {
			break
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("lock readiness")
		case <-time.After(50 * time.Millisecond):
		}
	}
	target := docker.Target{ID: "workflow-fixture/compose/project/db/postgres/frozen_override", Kind: "postgres", Source: f.p.Source, Database: "frozen_override"}
	h, e := startWorkflow(f.ctx, cfg, f.c, plan, []docker.Target{target})
	if e != nil {
		t.Fatal(e)
	}
	cleanupConcreteWorker(t, f, h.Worker)
	var active state.Record
	for {
		active, e = state.Observe(cfg.StateDir)
		if e != nil {
			t.Fatal(e)
		}
		if active.Phase == state.PhaseExecStarted {
			x, err := f.c.PollExec(f.ctx, active.ExecID)
			if err == nil && x.Running {
				break
			}
		}
		select {
		case <-f.ctx.Done():
			t.Fatal("checkpoint readiness")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if active.TargetID != targetHash(target.ID) {
		t.Fatal(active)
	}
	wp, e := f.c.TerminateWorker(f.ctx, h.Worker)
	if e != nil || !wp.Terminal {
		t.Fatal(wp, e)
	}
	o, e := state.Acquire(cfg.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	if e = o.NewRun(state.Record{RunID: "another", DaemonID: active.DaemonID, WorkerName: "new", Phase: state.PhaseIntent, Status: state.StatusActive}); !errors.Is(e, state.ErrOwned) {
		t.Fatal("worker death lost ownership", e)
	}
	o.Close()
	f.control("psql", "-XAt", "-U", "postgres", "-d", "frozen_override", "-c", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='workflow-lock-fixture'")
	select {
	case <-lockDone:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture lock did not exit")
	}
	result, e := WorkflowRecover(f.ctx, cfg)
	if e == nil || result.Status != "failed" || len(result.Targets) != 1 || result.Targets[0].Error != "backup failed" {
		t.Fatal(result, e)
	}
	if _, e = state.Observe(cfg.StateDir); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("fresh controller did not reconcile checkpoint", e)
	}
	if _, e = os.Stat(filepath.Join(cfg.StateDir, "last-result.json")); e != nil {
		t.Fatal(e)
	}
	if got := strings.TrimSpace(f.control("psql", "-XAt", "-U", "postgres", "-d", "frozen_override", "-c", "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+h.Worker.RunID+"'")); got != "0" {
		t.Fatal("source export session retained", got)
	}
	t.Log("one workflow worker killed while source export waited on frozen override DB; durable owner blocked overlap; fresh recovery proved exact source terminal and released failed, never success")
}
