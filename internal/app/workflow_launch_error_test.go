package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/tamntlib/bakabel/internal/state"
)

func TestRunReconcilesExactOwnedWorkerAfterStartResponseError(t *testing.T) {
	for _, boundary := range []string{"start", "create"} {
		t.Run(boundary, func(t *testing.T) { runOwnedLaunchFailureCase(t, boundary) })
	}
}

func TestRunPreservesOwnedRunIDWhenWaitAndCleanupLoseDocker(t *testing.T) {
	runOwnedLaunchFailureCase(t, "wait")
}

func TestServeStopsAfterScheduledOwnedWaitOutage(t *testing.T) {
	if os.Getenv("BAKABEL_SCHEDULE_FAILURE_TEST") != "1" {
		t.Skip("explicit real-minute scheduler failure fixture required")
	}
	runOwnedLaunchFailureCase(t, "serve-wait")
}

func runOwnedLaunchFailureCase(t *testing.T, boundary string) {
	t.Helper()
	waitFailure := strings.HasSuffix(boundary, "wait")
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: socket, StateDir: stateDir, WorkerImage: "sha256:" + strings.Repeat("d", 64), Timeout: time.Minute, Timezone: "UTC"}
	hostname, _ := os.Hostname()
	self, source, worker := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	name, run := "", ""
	var creates, starts, deletes atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p := req.URL.Path
		switch {
		case p == "/v1.55/info":
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case p == "/v1.55/containers/"+hostname+"/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": self, "State": map[string]any{"Running": true, "StartedAt": "2026-01-01T00:00:00Z"}, "Config": map[string]any{"Labels": map[string]string{"bakabel.installation": "fixture", "bakabel.role": "scheduler"}}, "Mounts": []map[string]any{{"Type": "bind", "Source": stateDir, "Destination": stateDir, "RW": true}, {"Type": "bind", "Source": "/node/repository", "Destination": "/repository", "RW": true}, {"Type": "bind", "Source": "/node/password", "Destination": "/password", "RW": false}, {"Type": "bind", "Source": socket, "Destination": socket, "RW": false}}})
		case p == "/v1.55/containers/json":
			json.NewEncoder(w).Encode([]map[string]any{{"Id": source, "Labels": map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.service": "db"}}})
		case p == "/v1.55/containers/"+source+"/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": source, "State": map[string]any{"Running": true, "StartedAt": "2026-01-01T00:00:00Z"}, "Config": map[string]any{"Env": []string{"POSTGRES_DB=fixture"}, "Labels": map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.service": "db", "bakabel.type": "postgres"}}})
		case p == "/v1.55/containers/create":
			creates.Add(1)
			name = req.URL.Query().Get("name")
			var body struct{ Labels map[string]string }
			json.NewDecoder(req.Body).Decode(&body)
			run = body.Labels["bakabel.run"]
			if boundary == "create" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, `{"Id":%q}`, worker)
		case p == "/v1.55/containers/"+worker+"/start":
			starts.Add(1)
			if waitFailure {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		case p == "/v1.55/containers/"+worker && req.Method == "DELETE":
			current, err := state.Observe(stateDir)
			if err != nil || current.RunID != run || current.WorkerContainerID != worker {
				t.Error("cleanup occurred after losing exact durable owner", current, err)
			}
			deletes.Add(1)
		case p == "/v1.55/containers/"+worker+"/json" || name != "" && p == "/v1.55/containers/"+name+"/json":
			if waitFailure && starts.Load() != 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if deletes.Load() != 0 {
				http.NotFound(w, req)
				return
			}
			status := "created"
			exit := 0
			if starts.Load() != 0 {
				status, exit = "exited", 137
			}
			fmt.Fprintf(w, `{"Id":%q,"Name":%q,"Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":%q,"Running":false,"Restarting":false,"Dead":false,"ExitCode":%d}}`, worker, "/"+name, run, status, exit)

		default:
			t.Errorf("unexpected launch-recovery API %s %s", req.Method, p)
			w.WriteHeader(500)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	var result WorkflowResult
	if boundary == "serve-wait" {
		cfg.Schedule = "* * * * *"
		ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
		defer cancel()
		var output, diagnostics bytes.Buffer
		err = Serve(ctx, cfg, &output, &diagnostics)
		if !errors.Is(err, errRecoveryBlocked) {
			t.Fatal("scheduler did not stop blocked after this invocation's wait outage", err, output.String())
		}
		var event serveEvent
		if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event) != nil || event.Result == nil {
			t.Fatal("scheduler did not emit exactly one identified result", output.String())
		}
		result = *event.Result
	} else {
		result, err = Run(context.Background(), cfg)
	}
	if err == nil {
		t.Fatal("lost start response was incorrectly reported successful")
	}
	if waitFailure {
		current, observeErr := state.Observe(stateDir)
		if observeErr != nil || current.RunID != run || result.RunID != run || creates.Load() != 1 || starts.Load() != 1 || deletes.Load() != 0 {
			t.Fatal("wait outage lost invocation identity or released/retried owned worker", result, current, observeErr)
		}
		return
	}
	if _, err = state.Observe(stateDir); !errors.Is(err, state.ErrNoRun) {
		t.Fatal("observable terminal worker was left unreconciled", err)
	}
	wantStarts := int32(1)
	if boundary == "create" {
		wantStarts = 0
	}
	if creates.Load() != 1 || starts.Load() != wantStarts || deletes.Load() != 1 {
		t.Fatal("create/start retried or exact cleanup missing", creates.Load(), starts.Load(), deletes.Load())
	}
}
