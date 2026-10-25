package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestWorkflowRecoversExactWorkerAlreadyAbsentAfterCleanup(t *testing.T) {
	cfg := healthConfig(t)
	cfg.DockerSocket = filepath.Join(cfg.StateDir, "socket")
	current := state.Record{RunID: strings.Repeat("b", 32), DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
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
	job := workflowJob{Version: 1, RunID: current.RunID, CreatedAt: time.Now(), Config: cfg, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if err = publishJSON(workflowDir(cfg), "job.json", job, maxWorkflowBytes); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", cfg.DockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("already-absent recovery issued %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Path == "/v1.55/info" {
			fmt.Fprint(w, `{"ID":"daemon"}`)
			return
		}
		http.NotFound(w, r)
	})}
	go server.Serve(listener)
	defer server.Close()
	result, err := WorkflowRecover(context.Background(), cfg)
	if err == nil || result.Status != "failed" {
		t.Fatal("recovery must not invent successful backup", result, err)
	}
	if _, err = state.Observe(cfg.StateDir); !errors.Is(err, state.ErrNoRun) {
		t.Fatal("exact absent worker could not finish owned cleanup", err)
	}
}
