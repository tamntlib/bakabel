package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestWorkflowWorkerExplicitNetworkAndFilePrivileges(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/create":
			var cfg struct {
				Env        []string
				HostConfig struct {
					NetworkMode     string
					CapAdd, CapDrop []string
				}
			}
			if e := json.NewDecoder(r.Body).Decode(&cfg); e != nil {
				t.Error(e)
			}
			if cfg.HostConfig.NetworkMode != "bridge" || !reflect.DeepEqual(cfg.HostConfig.CapAdd, []string{"DAC_READ_SEARCH", "CHOWN", "FOWNER", "DAC_OVERRIDE"}) || !reflect.DeepEqual(cfg.Env, []string{"RESTIC_PASSWORD_FILE=/run/secrets/restic-password", "AWS_SHARED_CREDENTIALS_FILE=/run/secrets/aws", "AWS_DEFAULT_REGION=fixture-region"}) {
				t.Errorf("unsafe workflow config %+v", cfg)
			}
			w.Write([]byte(`{"Id":"exact"}`))
		case "/v1.55/containers/exact/json":
			w.Write([]byte(`{"Id":"exact","Name":"/workflow","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":"run","bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"created","Running":false,"Restarting":false,"Dead":false,"ExitCode":0}}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(500)
		}
	})
	_, e := c.CreateWorker(context.Background(), Worker{DaemonID: "daemon", Name: "workflow", RunID: "run"}, WorkerSpec{Image: "fixture", Mode: "workflow", S3: true, S3Region: "fixture-region", Files: true})
	if e != nil {
		t.Fatal(e)
	}
}
