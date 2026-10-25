package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWorkerCreateFixedRestrictedContainer(t *testing.T) {
	created, started := false, false
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]string{"ID": "daemon"})
		case "/v1.55/containers/create":
			if r.URL.Query().Get("name") != "random-worker" {
				t.Error("name not pinned")
			}
			var cfg struct {
				Entrypoint, Cmd, Env []string
				Labels               map[string]string
				HostConfig           struct {
					AutoRemove     bool
					ReadonlyRootfs bool
					RestartPolicy  struct{ Name string }
					NanoCpus       int64
					Mounts         []struct {
						Type, Source, Target string
						ReadOnly             bool
					}
				}
			}
			if json.NewDecoder(r.Body).Decode(&cfg) != nil {
				t.Fatal("bad JSON")
			}
			if len(cfg.Env) != 0 || len(cfg.Cmd) != 1 || cfg.Cmd[0] != "_worker" || len(cfg.Entrypoint) != 1 || cfg.Entrypoint[0] != "/usr/local/bin/bakabel" || cfg.Labels["bakabel.run"] != "run" || cfg.Labels["bakabel.daemon"] != "daemon" || cfg.HostConfig.AutoRemove || !cfg.HostConfig.ReadonlyRootfs || cfg.HostConfig.RestartPolicy.Name != "no" || cfg.HostConfig.NanoCpus != 2000000000 || len(cfg.HostConfig.Mounts) != 1 || !cfg.HostConfig.Mounts[0].ReadOnly {
				t.Fatalf("unsafe cfg %+v", cfg)
			}
			created = true
			json.NewEncoder(w).Encode(map[string]string{"Id": "exact"})
		case "/v1.55/containers/exact/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "exact", "Name": "/random-worker", "Config": map[string]any{"Labels": map[string]string{"bakabel.worker": "1", "bakabel.run": "run", "bakabel.daemon": "daemon"}}, "HostConfig": map[string]any{"AutoRemove": false, "RestartPolicy": map[string]string{"Name": "no"}}, "State": map[string]any{"Status": "created", "Running": false, "Restarting": false, "Dead": false, "ExitCode": 0}})
		case "/v1.55/containers/exact/start":
			started = true
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	w, e := c.CreateWorker(context.Background(), Worker{DaemonID: "daemon", Name: "random-worker", RunID: "run"}, WorkerSpec{Image: "fixture", Mounts: []WorkerMount{{Source: "/job", Target: "/run/bakabel/job.json", ReadOnly: true}}})
	if e != nil || !created || w.ContainerID != "exact" || started {
		t.Fatalf("create %+v %v", w, e)
	}
	if e = c.StartWorker(context.Background(), w); e != nil || !started {
		t.Fatal("start", e)
	}
}
