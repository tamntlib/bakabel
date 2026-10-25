package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestLateWaiterInspectionErrorCannotCancelReplacementRun(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: filepath.Join(dir, "socket"), StateDir: dir, WorkerImage: "sha256:" + strings.Repeat("c", 64), Timeout: time.Minute, Timezone: "UTC"}
	old := state.Record{RunID: strings.Repeat("a", 32), DaemonID: "daemon", WorkerName: "old-worker", WorkerContainerID: "oldid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	replacement := old
	replacement.RunID, replacement.WorkerName, replacement.WorkerContainerID = strings.Repeat("b", 32), "replacement-worker", "replacementid"
	owner, err := state.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.NewRun(old); err != nil {
		t.Fatal(err)
	}
	owner.Close()
	if err = os.Mkdir(workflowDir(cfg), 0700); err != nil {
		t.Fatal(err)
	}
	created := time.Now().UTC()
	job := workflowJob{Version: 1, RunID: old.RunID, CreatedAt: created, Config: cfg, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if err = publishJSON(workflowDir(cfg), "job.json", job, maxWorkflowBytes); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", cfg.DockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	var infos, killed atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			if infos.Add(1) == 1 {
				// Another waiter finishes W1, then a launcher establishes W2 while
				// this waiter's W1 inspection is still in flight and will fail.
				o, e := state.Acquire(dir)
				if e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				defer o.Close()
				if e = o.Release(old, state.TerminalProof{WorkerTerminal: true, SourceTerminal: true}, state.Result{RunID: old.RunID, Status: state.OutcomeFailed}); e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				if e = o.NewRun(replacement); e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				job.RunID = replacement.RunID
				if e = os.Remove(filepath.Join(workflowDir(cfg), "job.json")); e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				if e = publishJSON(workflowDir(cfg), "job.json", job, maxWorkflowBytes); e != nil {
					t.Error(e)
				}
				w.WriteHeader(500)
				return
			}
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/replacementid/json":
			fmt.Fprintf(w, `{"Id":"replacementid","Name":"/replacement-worker","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"running","Running":true,"Restarting":false,"Dead":false,"ExitCode":0}}`, replacement.RunID)
		case "/v1.55/containers/replacementid/kill":
			killed.Add(1)
			w.WriteHeader(500)
		default:
			t.Errorf("unexpected waiter API %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	_, err = WorkflowWait(context.Background(), cfg, WorkflowHandle{Worker: recordWorker(old), CreatedAt: created})
	if err == nil {
		t.Fatal("stale waiter unexpectedly succeeded")
	}
	current, err := state.Observe(dir)
	if err != nil || current != replacement || killed.Load() != 0 {
		t.Fatal("late waiter acted on a replacement generation", current, err, killed.Load())
	}
}
