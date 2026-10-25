package app

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestHealthActiveRunDoesNotMaskLastFailure(t *testing.T) {
	cfg := healthConfig(t)
	cfg.Timeout = 2 * time.Hour
	now := time.Now().UTC()
	seedHealth(t, cfg, state.Result{RunID: "previous", Status: state.OutcomeFailed, Operation: "backup", FinishedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), LastBackupSuccessAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano)})
	current := state.Record{RunID: strings.Repeat("a", 32), DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	owner, err := state.Acquire(cfg.StateDir)
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
	job := workflowJob{Version: 1, RunID: current.RunID, CreatedAt: now.Add(-time.Second), Config: cfg, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if err = publishJSON(workflowDir(cfg), "job.json", job, maxWorkflowBytes); err != nil {
		t.Fatal(err)
	}
	report, err := Health(cfg, now)
	if err == nil || report.Overdue || report.ActiveRunID != current.RunID || report.LastResult == nil || report.LastResult.Status != state.OutcomeFailed {
		t.Fatal("new active run hid last failed outcome", report, err)
	}
}
