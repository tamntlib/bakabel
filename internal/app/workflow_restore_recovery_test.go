package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
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

func TestWorkflowRestoreCreatedGapUsesSavedIndependentToken(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			dir := t.TempDir()
			socket := filepath.Join(dir, "docker.sock")
			ln, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: socket, StateDir: dir, WorkerImage: "sha256:" + strings.Repeat("c", 64), Timeout: time.Minute, Timezone: "UTC"}
			run := strings.Repeat("a", 32)
			importRun := "restore_" + strings.Repeat("b", 48)
			started := "2026-01-01T00:00:00Z"
			target := docker.Target{ID: "source", Kind: "postgres", Source: docker.Source{DaemonID: "daemon", ContainerID: "target", StartedAt: started}, Database: "newdb"}
			j := workflowJob{Version: 1, RunID: run, CreatedAt: time.Now(), Config: cfg, Targets: []docker.Target{target}, Restore: &RestoreRequest{SnapshotID: strings.Repeat("d", 64), PostgresContainer: "target", Database: "newdb", User: "postgres"}}
			os.Mkdir(workflowDir(cfg), 0700)
			os.Mkdir(filepath.Join(workflowDir(cfg), "output"), 0700)
			if e = publishJSON(workflowDir(cfg), "job.json", j, maxWorkflowBytes); e != nil {
				t.Fatal(e)
			}
			o, e := state.Acquire(dir)
			if e != nil {
				t.Fatal(e)
			}
			r := state.Record{RunID: run, DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
			if e = o.NewRun(r); e != nil {
				t.Fatal(e)
			}
			r.TargetID = targetHash(target.ID)
			r.SourceContainerID = "target"
			r.SourceStartedAt = started
			r.ExecKind = "restore"
			r.Phase = state.PhaseCreatingExec
			if e = o.Save(r); e != nil {
				t.Fatal(e)
			}
			r.ImportRunID = importRun
			r.ExecID = "importexec"
			r.Phase = state.PhaseExecCreated
			if e = o.Save(r); e != nil {
				t.Fatal(e)
			}
			o.Close()
			removed := false
			outputs := map[string]string{}
			controls := 0
			tokenChecks := 0
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				p := req.URL.Path
				switch {
				case p == "/v1.55/info":
					fmt.Fprint(w, `{"ID":"daemon"}`)
				case p == "/v1.55/containers/workerid/json":
					if removed {
						http.NotFound(w, req)
						return
					}
					fmt.Fprintf(w, `{"Id":"workerid","Name":"/worker","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"exited","Running":false,"Restarting":false,"Dead":false,"ExitCode":137}}`, run)
				case p == "/v1.55/containers/worker/json":
					http.NotFound(w, req)
				case p == "/v1.55/containers/workerid" && req.Method == "DELETE":
					removed = true
				case p == "/v1.55/containers/target/json":
					fmt.Fprintf(w, `{"Id":"target","State":{"Running":true,"StartedAt":%q}}`, started)
				case p == "/v1.55/exec/importexec/json":
					json.NewEncoder(w).Encode(map[string]any{"ID": "importexec", "ContainerID": "target", "Running": false, "Pid": 0, "ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": []string{"--no-password", "--exit-on-error", "--dbname", "host='/var/run/postgresql' port='5432' user='postgres' dbname='newdb'"}}})
				case p == "/v1.55/containers/target/exec":
					var v docker.ExecConfig
					json.NewDecoder(req.Body).Decode(&v)
					joined := strings.Join(v.Cmd, " ")
					if !strings.Contains(joined, importRun) || strings.Contains(joined, run) {
						t.Error("wrong independent import token", v.Cmd)
					} else {
						tokenChecks++
					}
					controls++
					id := fmt.Sprintf("control%d", controls)
					if v.Cmd[0] == "/usr/local/bin/psql" {
						outputs[id] = "0\n"
					}
					fmt.Fprintf(w, `{"Id":%q}`, id)
				case strings.HasPrefix(p, "/v1.55/exec/control") && strings.HasSuffix(p, "/start"):
					id := strings.TrimSuffix(strings.TrimPrefix(p, "/v1.55/exec/"), "/start")
					body := []byte(outputs[id])
					header := make([]byte, 8)
					header[0] = 1
					binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
					w.Write(append(header, body...))
				case strings.HasPrefix(p, "/v1.55/exec/control") && strings.HasSuffix(p, "/json"):
					id := strings.TrimSuffix(strings.TrimPrefix(p, "/v1.55/exec/"), "/json")
					fmt.Fprintf(w, `{"ID":%q,"ContainerID":"target","Running":false,"ExitCode":0}`, id)
				default:
					t.Error("unexpected recovery API", req.Method, p)
					w.WriteHeader(500)
				}
			})}
			go srv.Serve(ln)
			defer srv.Close()
			var result WorkflowResult
			if allow {
				receipt := WorkflowResult{RunID: j.RunID, Status: "restored", Targets: []TargetResult{{TargetID: target.ID, Status: "restored", SnapshotID: j.Restore.SnapshotID}}}
				if e = publishJSON(filepath.Join(workflowDir(cfg), "output"), "result.json", receipt, maxWorkflowBytes); e != nil {
					t.Fatal(e)
				}
				client, _ := docker.NewClient(socket)
				result, e = finishWorkflow(context.Background(), cfg, client, docker.WorkerProof{Worker: recordWorker(r), Terminal: true, ExitCode: 0}, true)
			} else {
				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				result, e = WorkflowRecover(canceled, cfg)
			}
			if e == nil || result.Status != "failed" {
				t.Fatal(result, e)
			}
			if _, e = state.Observe(dir); !errors.Is(e, state.ErrNoRun) {
				t.Fatal("never-authorized import was not safely reconciled", e)
			}
			if !removed || tokenChecks < 2 {
				t.Fatal("restore terminal process/session proof missing", removed, tokenChecks)
			}
		})
	}
}
