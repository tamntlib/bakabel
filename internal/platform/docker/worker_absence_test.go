package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestPersistedWorkerAbsenceRequiresSameDaemonAndUnusedName(t *testing.T) {
	for _, mode := range []string{"absent", "name-reused", "daemon-wrong", "intent-only"} {
		t.Run(mode, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1.55/info" {
					id := "daemon"
					if mode == "daemon-wrong" {
						id = "wrong"
					}
					json.NewEncoder(w).Encode(map[string]string{"ID": id})
					return
				}
				if r.URL.Path == "/v1.55/containers/random/json" && mode == "name-reused" {
					json.NewEncoder(w).Encode(map[string]any{"Id": "different"})
					return
				}
				w.WriteHeader(404)
			})
			expected := Worker{DaemonID: "daemon", ContainerID: "persisted", Name: "random", RunID: "run"}
			if mode == "intent-only" {
				expected.ContainerID = ""
			}
			proof, e := c.InspectWorker(context.Background(), expected)
			if mode == "absent" {
				if e != nil || !proof.Terminal || proof.ExitCode != -1 {
					t.Fatal("lost removed-worker proof", proof, e)
				}
			} else if e == nil {
				t.Fatal("ambiguous absence authorized", proof)
			}
		})
	}
}
