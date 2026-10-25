package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestWorkerExactIdentityBeforeKill(t *testing.T) {
	for _, mode := range []string{"valid", "daemon", "labels", "name", "id", "unavailable", "restarting", "missing", "lost-create"} {
		t.Run(mode, func(t *testing.T) {
			killed := 0
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					id := "daemon"
					if mode == "daemon" {
						id = "other"
					}
					json.NewEncoder(w).Encode(map[string]any{"ID": id})
				case "/v1.55/containers/worker/json", "/v1.55/containers/bakabel-worker-0123456789abcdef0123456789abcdef/json":
					if mode == "unavailable" {
						w.WriteHeader(503)
						return
					}
					if mode == "missing" {
						w.WriteHeader(404)
						return
					}
					id, name, run := "worker", "/bakabel-worker-0123456789abcdef0123456789abcdef", "run"
					if mode == "id" {
						id = "replacement"
					}
					if mode == "name" {
						name = "/other"
					}
					if mode == "labels" {
						run = "other"
					}
					status := "running"
					if killed > 0 {
						status = "exited"
					}
					if mode == "restarting" {
						status = "restarting"
					}
					json.NewEncoder(w).Encode(map[string]any{"Id": id, "Name": name, "Config": map[string]any{"Labels": map[string]string{"bakabel.worker": "1", "bakabel.run": run, "bakabel.daemon": "daemon"}}, "HostConfig": map[string]any{"AutoRemove": false, "RestartPolicy": map[string]any{"Name": "no"}}, "State": map[string]any{"Status": status, "Running": killed == 0, "Restarting": mode == "restarting", "Dead": false, "ExitCode": 137}})
				case "/v1.55/containers/worker/kill":
					if r.URL.Query().Get("signal") != "KILL" {
						t.Error("not exact KILL")
					}
					killed++
					w.WriteHeader(204)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(500)
				}
			})
			worker := Worker{DaemonID: "daemon", ContainerID: "worker", Name: "bakabel-worker-0123456789abcdef0123456789abcdef", RunID: "run"}
			if mode == "lost-create" || mode == "missing" {
				worker.ContainerID = ""
			}
			got, e := c.TerminateWorker(context.Background(), worker)
			if mode == "valid" || mode == "lost-create" {
				if e != nil || !got.Terminal || got.Worker.ContainerID != "worker" || killed != 1 {
					t.Fatalf("proof=%+v err=%v kills=%d", got, e, killed)
				}
			} else if !errors.Is(e, ErrQuarantine) || killed != 0 {
				t.Fatalf("identity uncertainty signalled worker: %+v %v kills=%d", got, e, killed)
			}
		})
	}
}
