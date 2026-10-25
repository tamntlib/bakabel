package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestWorkflowCleanupFailureRetainsDurableOwner(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: filepath.Join(dir, "absent.sock"), StateDir: dir, WorkerImage: "sha256:" + strings.Repeat("c", 64), Timeout: time.Minute, Timezone: "UTC"}
	current := state.Record{RunID: strings.Repeat("b", 32), DaemonID: "daemon", WorkerName: "current-worker", WorkerContainerID: "current-id", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	owner, err := state.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.NewRun(current); err != nil {
		t.Fatal(err)
	}
	owner.Close()
	if err = os.Mkdir(workflowDir(cfg), 0700); err != nil {
		t.Fatal(err)
	}
	job := workflowJob{Version: 1, RunID: current.RunID, CreatedAt: time.Now(), Config: cfg, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if err = publishJSON(workflowDir(cfg), "job.json", job, maxWorkflowBytes); err != nil {
		t.Fatal(err)
	}
	client, err := docker.NewClient(cfg.DockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	_, err = finishWorkflow(context.Background(), cfg, client, docker.WorkerProof{Worker: recordWorker(current), Terminal: true, ExitCode: 137}, false)
	if err == nil {
		t.Fatal("cleanup without Engine proof succeeded")
	}
	got, err := state.Observe(dir)
	if err != nil || got != current {
		t.Fatalf("cleanup failure lost recovery anchor: got=%#v err=%v", got, err)
	}
	if _, err = state.ObserveResult(dir); !errors.Is(err, state.ErrNoResult) {
		t.Fatal("published completion before exact worker cleanup", err)
	}
}
