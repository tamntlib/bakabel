package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

// This is deliberately a NATIVE-PATH CONTRACT, not a Docker volume acceptance
// claim. Docker inventory is a controlled HTTP fixture; source/target file
// identity, Restic readback, descriptor-pinned restore and permissions are real.
// Every filesystem root is disposable; production consumer volumes are never
// mounted or read to make this test pass.
func TestWorkflowFilesNativeDirectoryContract(t *testing.T) {
	if os.Getenv("RESTIC_TEST_BINARY") == "" {
		t.Skip("explicit disposable real Restic fixture required")
	}
	ctx := context.Background()
	repo := repoFixture(t, ctx)
	root := t.TempDir()
	sourceID := "native-contract/" + targetHash(root)
	source := files.WorkerPath(sourceID, "/data")
	if e := os.MkdirAll(source, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(source)
	payload := filepath.Join(source, "payload")
	if e := os.WriteFile(payload, []byte("native-file-roundtrip\n"), 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(payload, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chown(payload, 1234, 2345); e != nil {
		t.Fatal(e)
	}
	m, e := files.Capture("native-contract", sourceID, files.Volume{DaemonID: "daemon", NodeID: "node", Name: "lost-source-volume", Mountpoint: source, Destination: "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	result := repo.Backup(ctx, m, "native-contract", files.Hostname("native-contract"), []string{"--group-by", "host,paths", "--", source})
	if result.Err != nil {
		t.Fatal(result)
	}
	destinations := map[bool]string{false: filepath.Join(root, "unavailable-target"), true: filepath.Join(root, "visible-target")}
	for _, p := range destinations {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.RemoveAll(source); e != nil {
		t.Fatal(e)
	}
	var repository string
	for _, v := range repo.Env {
		if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
			repository = strings.TrimPrefix(v, "RESTIC_REPOSITORY=")
		}
	}
	for _, visible := range []bool{false, true} {
		t.Run(fmt.Sprint(visible), func(t *testing.T) {
			stateDir := t.TempDir()
			destination := destinations[visible]
			consumer := filepath.Join(root, "consumer")
			if visible {
				os.Mkdir(consumer, 0700)
			} else {
				consumer = "/unavailable/native-consumer"
			}
			socket := filepath.Join(t.TempDir(), "docker.sock")
			ln, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			run := strings.Repeat("a", 32)
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					fmt.Fprint(w, `{"ID":"daemon"}`)
				case "/v1.55/containers/workerid/json":
					fmt.Fprintf(w, `{"Id":"workerid","Name":"/worker","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":%q,"bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"running","Running":true,"StartedAt":"2026-01-01T00:00:00Z","Restarting":false,"Dead":false,"ExitCode":0}}`, run)
				case "/v1.55/containers/json":
					fmt.Fprint(w, `[{"Id":"workerid"},{"Id":"consumer"}]`)
				case "/v1.55/containers/consumer/json":
					fmt.Fprintf(w, `{"Id":"consumer","State":{"Running":false,"StartedAt":"2026-01-01T00:00:00Z"},"Mounts":[{"Type":"bind","Source":%q,"Destination":"/application"}]}`, consumer)
				default:
					t.Error(r.URL.Path)
					w.WriteHeader(500)
				}
			})}
			go srv.Serve(ln)
			defer srv.Close()
			client, _ := docker.NewClient(socket)
			o, e := state.Acquire(stateDir)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			r := state.Record{RunID: run, DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
			if e = o.NewRun(r); e != nil {
				t.Fatal(e)
			}
			j := workflowJob{RunID: run, Config: config.Config{Installation: "native-contract", StateDir: stateDir, Repository: repository}, Restore: &RestoreRequest{SnapshotID: result.SnapshotID, Directory: destination}}
			if visible {
				snap, err := exactSnapshot(ctx, repo, result.SnapshotID)
				if err != nil {
					t.Fatal(err)
				}
				worker := recordWorker(r)
				probe, err := client.PreflightFileRestoreDirectory(ctx, snap, destination, &worker, stateDir, repository)
				if err != nil {
					t.Fatal("native positive preflight", err)
				}
				probe.Close()
			}
			tr := restoreFilesTarget(ctx, o, client, repo, j, docker.Target{ID: sourceID, Kind: "volume"})
			if !visible {
				if tr.Error != "restore failed" || tr.Status == "restored" {
					t.Fatal("opaque consumer falsely accepted", tr)
				}
				entries, _ := os.ReadDir(destination)
				if len(entries) != 0 {
					t.Fatal("preflight wrote destination")
				}
				return
			}
			if tr.Error != "" || tr.Status != "restored" {
				t.Fatal(tr)
			}
			body, e := os.ReadFile(filepath.Join(destination, "payload"))
			if e != nil || string(body) != "native-file-roundtrip\n" {
				t.Fatal(string(body), e)
			}
			st, e := os.Stat(filepath.Join(destination, "payload"))
			if e != nil {
				t.Fatal(e)
			}
			raw := st.Sys().(*syscall.Stat_t)
			if st.Mode().Perm() != 0640 || raw.Uid != 1234 || raw.Gid != 2345 {
				t.Fatal(st.Mode(), raw.Uid, raw.Gid)
			}
			t.Log("real Restic, lost source, fresh state, native physical consumer checks, flattened directory, mode0640 uid1234 gid2345; not a Docker volume acceptance claim")
		})
	}
}
