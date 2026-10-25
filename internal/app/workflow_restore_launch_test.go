package app

// This tests PUBLIC Restore with a real disposable Restic repository and a unit
// Engine seam. It does not claim Docker file-restore or real PG-import acceptance.
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

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestRestoreReconcilesExactWorkerAfterLaunchResponseLoss(t *testing.T) {
	if os.Getenv("RESTIC_TEST_BINARY") != "/usr/bin/restic" {
		t.Skip("explicit real Restic binary at the production path required")
	}
	for _, kind := range []string{"volume", "postgres"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			repo := repoFixture(t, ctx)
			var m backup.Metadata
			var args []string
			if kind == "volume" {
				id := "restore-launch/" + targetHash(t.TempDir())
				source := files.WorkerPath(id, "/data")
				if err := os.MkdirAll(source, 0700); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(source) })
				if err := os.WriteFile(filepath.Join(source, "payload"), []byte("synthetic launch fixture"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				m, err = files.Capture("fixture", id, files.Volume{DaemonID: "old-daemon", NodeID: "old-node", Name: "old-volume", Mountpoint: source, Destination: "/data"}, source)
				if err != nil {
					t.Fatal(err)
				}
				args = []string{"--", source}
			} else {
				m = backup.Metadata{Version: 1, Kind: "postgres", Source: "old/postgres", Paths: []string{"/dump"}, Postgres: &backup.PostgresMetadata{Database: "fixture", ClusterID: "123", DatabaseOID: "456", ServerVersion: 180006, ClientVersion: 180006, Format: "custom", Owner: "owner", ACL: []backup.Grant{}}}
				args = []string{"--stdin-from-command", "--stdin-filename", "dump", "--", "/bin/sh", "-c", "printf synthetic-launch-fixture"}
			}
			snap := repo.Backup(ctx, m, "previous", "fixture", args)
			if snap.Err != nil {
				t.Fatal(snap)
			}
			for _, boundary := range []string{"create", "start", "create-unknown", "start-unknown"} {
				t.Run(boundary, func(t *testing.T) { restoreLostLaunchCase(t, repo, snap.SnapshotID, kind, boundary) })
			}
		})
	}
}

func restoreLostLaunchCase(t *testing.T, repo backup.Repository, snapshot, kind, boundary string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	socket := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, DockerSocket: socket, StateDir: dir, WorkerImage: "sha256:" + strings.Repeat("d", 64), Timeout: time.Minute, Timezone: "UTC"}
	for _, v := range repo.Env {
		if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
			cfg.Repository = strings.TrimPrefix(v, "RESTIC_REPOSITORY=")
		}
		if strings.HasPrefix(v, "RESTIC_PASSWORD_FILE=") {
			cfg.Credentials.PasswordFile = strings.TrimPrefix(v, "RESTIC_PASSWORD_FILE=")
		}
	}
	hostname, _ := os.Hostname()
	worker := strings.Repeat("c", 64)
	target := strings.Repeat("b", 64)
	var name, run string
	creates, starts, deletes, controls := 0, 0, 0, 0
	outputs := map[string]string{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/v1.55/info":
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case p == "/v1.55/containers/"+hostname+"/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": strings.Repeat("a", 64), "State": map[string]any{"Running": true, "StartedAt": "2026-01-01T00:00:00Z"}, "Config": map[string]any{"Labels": map[string]string{"bakabel.installation": "fixture", "bakabel.role": "scheduler"}}, "Mounts": []map[string]any{{"Type": "bind", "Source": dir, "Destination": dir, "RW": true}, {"Type": "bind", "Source": cfg.Repository, "Destination": cfg.Repository, "RW": true}, {"Type": "bind", "Source": cfg.Credentials.PasswordFile, "Destination": cfg.Credentials.PasswordFile, "RW": false}, {"Type": "bind", "Source": socket, "Destination": socket, "RW": false}}})
		case p == "/v1.55/containers/json":
			fmt.Fprint(w, `[]`)
		case p == "/v1.55/containers/"+target+"/json":
			fmt.Fprintf(w, `{"Id":%q,"State":{"Running":true,"StartedAt":"2026-01-01T00:00:00Z"}}`, target)
		case p == "/v1.55/containers/"+target+"/exec":
			var request docker.ExecConfig
			json.NewDecoder(r.Body).Decode(&request)
			controls++
			id := fmt.Sprintf("control%d", controls)
			if len(request.Cmd) == 2 && request.Cmd[1] == "--version" {
				outputs[id] = strings.TrimPrefix(request.Cmd[0], "/usr/local/bin/") + " (PostgreSQL) 18.6\n"
			} else if strings.Contains(request.Cmd[len(request.Cmd)-1], "pg_control_system") {
				outputs[id] = `{"database":"fixture","cluster_id":"789","database_oid":"100","server_version":180006,"format":"custom","owner":"owner","acl":[],"superuser":true}`
			} else {
				outputs[id] = `{"objects":[],"extensions":[{"name":"plpgsql","schema":"pg_catalog","version":"1.0"}],"namespaces":["public"],"global_objects":[{"kind":"language","name":"c"},{"kind":"language","name":"internal"},{"kind":"language","name":"plpgsql"},{"kind":"language","name":"sql"}],"namespace_policies":[{"acl":[{"grantee":"PUBLIC","grantor":"pg_database_owner","privilege":"USAGE","grant_option":false},{"grantee":"pg_database_owner","grantor":"pg_database_owner","privilege":"CREATE","grant_option":false},{"grantee":"pg_database_owner","grantor":"pg_database_owner","privilege":"USAGE","grant_option":false}],"name":"public","owner":"pg_database_owner"}]}`
			}
			fmt.Fprintf(w, `{"Id":%q}`, id)
		case strings.HasPrefix(p, "/v1.55/exec/control") && strings.HasSuffix(p, "/start"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/v1.55/exec/"), "/start")
			data := []byte(outputs[id])
			header := make([]byte, 8)
			header[0] = 1
			binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
			w.Write(append(header, data...))
		case strings.HasPrefix(p, "/v1.55/exec/control") && strings.HasSuffix(p, "/json"):
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/v1.55/exec/"), "/json")
			fmt.Fprintf(w, `{"ID":%q,"ContainerID":%q,"Running":false,"ExitCode":0}`, id, target)
		case p == "/v1.55/containers/create":
			creates++
			name = r.URL.Query().Get("name")
			var body struct{ Labels map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			run = body.Labels["bakabel.run"]
			if strings.HasPrefix(boundary, "create") {
				w.WriteHeader(500)
			} else {
				fmt.Fprintf(w, `{"Id":%q}`, worker)
			}
		case p == "/v1.55/containers/"+worker+"/start":
			starts++
			w.WriteHeader(500)
		case p == "/v1.55/containers/"+worker && r.Method == "DELETE":
			owner, err := state.Observe(dir)
			if err != nil || owner.RunID != run || owner.WorkerContainerID != worker {
				t.Error("cleanup lost durable identity", owner, err)
			}
			deletes++
		case p == "/v1.55/containers/"+worker+"/json" || name != "" && p == "/v1.55/containers/"+name+"/json":
			if strings.HasSuffix(boundary, "unknown") && (strings.HasPrefix(boundary, "create") || starts != 0) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if deletes != 0 {
				http.NotFound(w, r)
				return
			}
			status := "created"
			exit := 0
			if starts != 0 {
				status = "exited"
				exit = 137
			}
			labelRun := run
			fmt.Fprintf(w, `{"Id":%q,"Name":%q,"Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":%q,"Running":false,"Restarting":false,"Dead":false,"ExitCode":%d}}`, worker, "/"+name, labelRun, status, exit)
		default:
			t.Errorf("unexpected restore launch API %s %s", r.Method, p)
			w.WriteHeader(500)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	req := RestoreRequest{SnapshotID: snapshot, Directory: t.TempDir()}
	if kind == "postgres" {
		req = RestoreRequest{SnapshotID: snapshot, PostgresContainer: target, Database: "fixture", User: "postgres"}
	}
	result, err := Restore(ctx, cfg, req)
	if err == nil || creates != 1 || result.RunID != run || run == "" {
		t.Fatal("restore never reached or lost launch invocation", result, err, creates, run)
	}
	owner, observeErr := state.Observe(dir)
	if strings.HasSuffix(boundary, "unknown") {
		if observeErr != nil || owner.RunID != run || deletes != 0 {
			t.Fatal("unproven worker released or deleted", owner, observeErr, deletes)
		}
	} else if !errors.Is(observeErr, state.ErrNoRun) || deletes != 1 {
		t.Fatal("exact terminal restore worker left unreconciled", owner, observeErr, deletes)
	}
	expectedStarts := 1
	if strings.HasPrefix(boundary, "create") {
		expectedStarts = 0
	}
	if starts != expectedStarts {
		t.Fatal("restore create/start retried", creates, starts)
	}
	if kind == "postgres" && controls != 4 {
		t.Fatal("restore did not pass read-only PG preflight", controls)
	}
}
