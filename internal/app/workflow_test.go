package app

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestWorkflowCurrentObservesWithoutTakingWorkerGuard(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: "/docker.sock", StateDir: dir, WorkerImage: "sha256:" + strings.Repeat("a", 64), Timeout: time.Minute, Timezone: "UTC"}
	o, e := state.Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := state.Record{RunID: strings.Repeat("b", 32), DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	os.Mkdir(workflowDir(cfg), 0700)
	created := time.Now().Add(-time.Hour).UTC()
	j := workflowJob{Version: 1, RunID: r.RunID, Config: cfg, CreatedAt: created, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if e = publishJSON(workflowDir(cfg), "job.json", j, maxWorkflowBytes); e != nil {
		t.Fatal(e)
	}
	h, e := WorkflowCurrent(cfg)
	if e != nil || h.Worker != recordWorker(r) || !h.CreatedAt.Equal(created) {
		t.Fatal(h, e)
	}
}

func TestWorkflowStartOneWorkerClosesGuardBeforeStart(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	os.Mkdir(stateDir, 0700)
	socket := filepath.Join(dir, "socket")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	hostname, _ := os.Hostname()
	source := strings.Repeat("b", 64)
	worker := strings.Repeat("c", 64)
	self := strings.Repeat("a", 64)
	created, started := 0, 0
	name, run := "", ""
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/" + hostname + "/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": self, "State": map[string]any{"Running": true, "StartedAt": "2026-01-01T00:00:00Z"}, "Config": map[string]any{"Labels": map[string]string{"bakabel.installation": "fixture", "bakabel.role": "scheduler"}}, "Mounts": []map[string]any{{"Type": "bind", "Source": stateDir, "Destination": stateDir, "RW": true}, {"Type": "bind", "Source": "/node/repo", "Destination": "/repository", "RW": true}, {"Type": "bind", "Source": "/node/pass", "Destination": "/password", "RW": false}, {"Type": "bind", "Source": socket, "Destination": socket, "RW": false}}})
		case "/v1.55/containers/json":
			json.NewEncoder(w).Encode([]any{map[string]any{"Id": source, "Labels": map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.service": "db"}}})
		case "/v1.55/containers/" + source + "/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": source, "State": map[string]any{"Running": true, "StartedAt": "2026-01-01T00:00:00Z"}, "Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "fixture", "com.docker.compose.service": "db", "bakabel.type": "postgres"}, "Env": []string{"POSTGRES_DB=fixture"}}})
		case "/v1.55/containers/create":
			created++
			name = r.URL.Query().Get("name")
			var cfg struct {
				Cmd        []string
				Labels     map[string]string
				HostConfig struct{ NanoCpus, Memory int64 }
			}
			json.NewDecoder(r.Body).Decode(&cfg)
			run = cfg.Labels["bakabel.run"]
			if len(cfg.Cmd) != 1 || cfg.Cmd[0] != "_workflow" {
				t.Error(cfg)
			}
			if cfg.HostConfig.NanoCpus != 1_000_000_000 || cfg.HostConfig.Memory != 384*(1<<20) {
				t.Error("workflow resource override lost", cfg.HostConfig)
			}
			fmt.Fprintf(w, `{"Id":%q}`, worker)
		case "/v1.55/containers/" + worker + "/json":
			fmt.Fprintf(w, `{"Id":%q,"Name":%q,"Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"created","Running":false,"Restarting":false,"Dead":false,"ExitCode":0}}`, worker, "/"+name, run)
		case "/v1.55/containers/" + worker + "/start":
			started++
			o, e := state.Acquire(stateDir)
			if e != nil {
				t.Error("launcher guard still held at start", e)
				return
			}
			defer o.Close()
			rec, e := o.Load()
			if e != nil || !rec.WorkerStartAuthorized || rec.WorkerContainerID != worker || rec.SourceContainerID != "" {
				t.Error(rec, e)
			}
		default:
			t.Error("unexpected API", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	c := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: socket, StateDir: stateDir, WorkerImage: "sha256:" + strings.Repeat("d", 64), Timeout: time.Minute, Timezone: "UTC"}
	c.WorkerResources = config.WorkerResources{CPUs: 1, MemoryMiB: 384}
	h, e := WorkflowStart(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if created != 1 || started != 1 || h.Worker.ContainerID != worker {
		t.Fatal(created, started, h)
	}
	var j workflowJob
	if e = readJSON(filepath.Join(stateDir, "workflow", "job.json"), &j, maxWorkflowBytes); e != nil {
		t.Fatal(e)
	}
	if len(j.Targets) != 1 || j.Targets[0].ID != "fixture/compose/fixture/db/postgres/fixture" || j.CreatedAt.IsZero() {
		t.Fatal(j)
	}
}
