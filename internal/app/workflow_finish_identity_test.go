package app

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestFinishWorkflowRejectsStaleTerminalWorkerProof(t *testing.T) {
	for _, field := range []string{"run", "daemon", "name", "container"} {
		t.Run(field, func(t *testing.T) {
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
			stale := recordWorker(current)
			switch field {
			case "run":
				stale.RunID = strings.Repeat("a", 32)
			case "daemon":
				stale.DaemonID = "old-daemon"
			case "name":
				stale.Name = "old-worker"
			case "container":
				stale.ContainerID = "old-id"
			}
			client, err := docker.NewClient(cfg.DockerSocket)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", cfg.DockerSocket)
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				t.Errorf("stale proof attempted Docker access: %s %s", req.Method, req.URL.Path)
				w.WriteHeader(http.StatusInternalServerError)
			})}
			go server.Serve(listener)
			defer server.Close()
			_, err = finishWorkflow(context.Background(), cfg, client, docker.WorkerProof{Worker: stale, Terminal: true, ExitCode: 137}, false)
			if err == nil {
				t.Fatal("accepted stale terminal proof")
			}
			got, observeErr := state.Observe(dir)
			if observeErr != nil || got != current {
				t.Fatalf("stale proof released or changed newer ownership: got=%#v err=%v", got, observeErr)
			}
			if _, err = state.ObserveResult(dir); err != state.ErrNoResult {
				t.Fatalf("stale waiter wrote a receipt for another run: %v", err)
			}
		})
	}
}
