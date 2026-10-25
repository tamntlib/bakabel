package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
)

func TestWorkerResourceDefaultsAndOverridesReachEngine(t *testing.T) {
	for _, tc := range []struct {
		resources    config.WorkerResources
		cpus, memory int64
	}{
		{config.WorkerResources{}, 2, 512},
		{config.WorkerResources{CPUs: 1, MemoryMiB: 384}, 1, 384},
	} {
		c := server(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/v1.55/info":
				w.Write([]byte(`{"ID":"daemon"}`))
			case "/v1.55/containers/create":
				var body struct {
					HostConfig struct {
						NanoCpus, Memory int64
						CpusetCpus       string
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body.HostConfig.NanoCpus != tc.cpus*1_000_000_000 || body.HostConfig.Memory != tc.memory*(1<<20) || body.HostConfig.CpusetCpus != "" {
					t.Error("wrong resource policy", body)
				}
				w.Write([]byte(`{"Id":"exact"}`))
			case "/v1.55/containers/exact/json":
				w.Write([]byte(`{"Id":"exact","Name":"/worker","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":"run","bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"created","Running":false,"Restarting":false,"Dead":false,"ExitCode":0}}`))
			default:
				t.Error("unexpected API", r.URL.Path)
				w.WriteHeader(500)
			}
		})
		if _, err := c.CreateWorker(context.Background(), Worker{DaemonID: "daemon", Name: "worker", RunID: "run"}, WorkerSpec{Image: "fixture", Resources: tc.resources}); err != nil {
			t.Fatal(err)
		}
	}
}
