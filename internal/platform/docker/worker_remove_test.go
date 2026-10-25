package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestRemoveWorkerRequiresVerifiedTerminalAndReadback(t *testing.T) {
	for _, mode := range []string{"terminal", "running", "wrong-labels", "delete-lost", "readback-present"} {
		t.Run(mode, func(t *testing.T) {
			removed := false
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1.55/info" {
					json.NewEncoder(w).Encode(map[string]string{"ID": "daemon"})
					return
				}
				if r.Method == "DELETE" {
					if r.URL.Path != "/v1.55/containers/exact" || r.URL.RawQuery != "" {
						t.Error("not exact/nonforce removal", r.URL)
					}
					if mode == "delete-lost" {
						w.WriteHeader(503)
						return
					}
					removed = true
					w.WriteHeader(204)
					return
				}
				if removed && mode != "readback-present" {
					w.WriteHeader(404)
					return
				}
				run, status := "run", "exited"
				running := mode == "running"
				if running {
					status = "running"
				}
				if mode == "wrong-labels" {
					run = "other"
				}
				json.NewEncoder(w).Encode(map[string]any{"Id": "exact", "Name": "/worker", "Config": map[string]any{"Labels": map[string]string{"bakabel.worker": "1", "bakabel.run": run, "bakabel.daemon": "daemon"}}, "HostConfig": map[string]any{"AutoRemove": false, "RestartPolicy": map[string]string{"Name": "no"}}, "State": map[string]any{"Status": status, "Running": running, "Restarting": false, "Dead": false, "ExitCode": 0}})
			})
			e := c.RemoveWorker(context.Background(), Worker{DaemonID: "daemon", ContainerID: "exact", Name: "worker", RunID: "run"})
			if mode == "terminal" {
				if e != nil || !removed {
					t.Fatal("terminal not removed", e)
				}
			} else {
				if e == nil {
					t.Fatal("uncertain removal accepted")
				}
				if (mode == "running" || mode == "wrong-labels") && removed {
					t.Fatal("unproven worker removed")
				}
			}
		})
	}
}
