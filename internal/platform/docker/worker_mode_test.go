package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestWorkflowWorkerModeIsFixedAndRejectsArbitraryCommands(t *testing.T) {
	created := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/create":
			var cfg struct{ Cmd, Entrypoint []string }
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				t.Error(err)
			}
			if len(cfg.Cmd) != 1 || cfg.Cmd[0] != "_workflow" || len(cfg.Entrypoint) != 1 || cfg.Entrypoint[0] != "/usr/local/bin/bakabel" {
				t.Error("non-fixed command", cfg)
			}
			created++
			w.Write([]byte(`{"Id":"exact"}`))
		case "/v1.55/containers/exact/json":
			w.Write([]byte(`{"Id":"exact","Name":"/workflow","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":"run","bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"created","Running":false,"Restarting":false,"Dead":false,"ExitCode":0}}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(500)
		}
	})
	worker := Worker{DaemonID: "daemon", Name: "workflow", RunID: "run"}
	if _, err := c.CreateWorker(context.Background(), worker, WorkerSpec{Image: "fixture", Mode: "workflow"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateWorker(context.Background(), worker, WorkerSpec{Image: "fixture", Mode: "sh -c unsafe"}); err == nil {
		t.Fatal("arbitrary command accepted")
	}
	if created != 1 {
		t.Fatalf("invalid mode performed create: %d", created)
	}
}
