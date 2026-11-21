package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func frame(stream byte, data []byte) []byte {
	var hdr [8]byte
	hdr[0] = stream
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(data)))
	return append(hdr[:], data...)
}

func TestDemuxAndDumpStream(t *testing.T) {
	var wire bytes.Buffer
	wire.Write(frame(1, []byte("PGDMPhello world")))
	wire.Write(frame(2, []byte("pg_dump notice\n")))
	wire.Write(frame(1, []byte(DumpCompletionPrefix+"run42\x00")))

	var out, errBuf bytes.Buffer
	ds := NewDumpStream(&out, "run42")
	if err := Demux(&wire, ds, &errBuf); err != nil {
		t.Fatalf("Demux error: %v", err)
	}
	if err := ds.Finish(); err != nil {
		t.Fatalf("DumpStream.Finish error: %v", err)
	}
	if out.String() != "PGDMPhello world" {
		t.Fatalf("stdout = %q, want stripped archive", out.String())
	}
	if errBuf.String() != "pg_dump notice\n" {
		t.Fatalf("stderr = %q", errBuf.String())
	}

	// Truncated stream without completion marker must fail Finish.
	var trunc bytes.Buffer
	ds2 := NewDumpStream(&trunc, "run42")
	_, _ = ds2.Write([]byte("PGDMPpartial"))
	if err := ds2.Finish(); err == nil {
		t.Fatal("expected truncated stream to fail Finish")
	}
}

func startFakeDocker(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	c, err := NewClient(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestDiscoverSwarmPlacementAndLabels(t *testing.T) {
	c := startFakeDocker(t, func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1.55")
		switch p {
		case "/_ping":
			w.Header().Set("Api-Version", "1.55")
			_, _ = w.Write([]byte("OK"))
		case "/info":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ID": "daemon-1",
				"Swarm": map[string]any{
					"LocalNodeState":   "active",
					"NodeID":           "node-mgr",
					"ControlAvailable": true,
				},
			})
		case "/services":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"ID": "svc-pg",
					"Spec": map[string]any{
						"Name": "llmproxy-data_db",
						"Labels": map[string]string{
							"com.docker.stack.namespace": "llmproxy-data",
							"bakabel.type":               "postgres",
						},
					},
				},
				{
					"ID": "svc-vol",
					"Spec": map[string]any{
						"Name": "app_files",
						"Labels": map[string]string{
							"com.docker.stack.namespace": "app",
							"bakabel.type":               "volume",
							"bakabel.paths":              "/data",
						},
					},
				},
			})
		case "/tasks":
			if strings.Contains(r.URL.RawQuery, "svc-pg") {
				_ = json.NewEncoder(w).Encode([]map[string]any{{
					"ID": "t1", "ServiceID": "svc-pg", "NodeID": "node-mgr",
					"Status": map[string]any{"State": "running", "ContainerStatus": map[string]any{"ContainerID": "ctr-pg"}},
				}})
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"ID": "t2", "ServiceID": "svc-vol", "NodeID": "node-other",
				"Status": map[string]any{"State": "running", "ContainerStatus": map[string]any{"ContainerID": "ctr-vol"}},
			}})
		case "/containers/ctr-pg/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id":    "ctr-pg",
				"State": map[string]any{"Running": true, "StartedAt": "2026-11-21T00:00:00Z"},
				"Config": map[string]any{
					"Env": []string{"POSTGRES_USER=app", "POSTGRES_DB=litellm", "POSTGRES_PASSWORD=secret"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// Scoped to llmproxy-data succeeds and discovers Postgres target.
	res, err := Discover(context.Background(), c, DiscoverOptions{Platform: "auto", Scope: []string{"llmproxy-data"}})
	if err != nil {
		t.Fatalf("Discover scoped failed: %v", err)
	}
	if res.Platform != "swarm" || len(res.Targets) != 1 {
		t.Fatalf("unexpected discover result: %+v", res)
	}
	got := res.Targets[0]
	if got.ID != "llmproxy-data/db/postgres/litellm" || got.DBUser != "app" || got.Database != "litellm" {
		t.Fatalf("unexpected target: %+v", got)
	}

	// Unscoped hits app_files on node-other and fails closed on placement.
	if _, err := Discover(context.Background(), c, DiscoverOptions{Platform: "auto"}); err == nil || !strings.Contains(err.Error(), "unsupported placement") {
		t.Fatalf("expected unsupported placement error, got: %v", err)
	}
}
