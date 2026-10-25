package docker

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestMissingRunningFlagIsUnknown(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"StartedAt":"start"}}`))
		case "/v1.55/exec/export/json":
			w.Write([]byte(`{"ID":"export","ContainerID":"source","ExitCode":0}`))
		default:
			w.WriteHeader(404)
		}
	})
	if _, e := c.CheckSource(context.Background(), Source{"daemon", "source", "start"}); !errors.Is(e, ErrQuarantine) {
		t.Error("missing source Running released ownership", e)
	}
	if _, e := c.WaitExec(context.Background(), "export"); !errors.Is(e, ErrQuarantine) {
		t.Error("missing exec Running became success", e)
	}
}
func TestSourceTerminalOnlyOnSameDaemon(t *testing.T) {
	for _, tc := range []struct {
		name, daemon, container string
		code                    int
		want                    SourceStatus
	}{
		{"missing", "daemon", "", 404, SourceTerminal},
		{"daemon-mismatch", "different", "", 404, SourceUnknown},
		{"old-incarnation", "daemon", `{"Id":"source","State":{"Running":true,"StartedAt":"new"}}`, 200, SourceTerminal},
		{"stopped", "daemon", `{"Id":"source","State":{"Running":false,"StartedAt":"start"}}`, 200, SourceTerminal},
		{"wrong-container", "daemon", `{"Id":"replacement","State":{"Running":false,"StartedAt":"start"}}`, 200, SourceUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1.55/info" {
					w.Write([]byte(`{"ID":"` + tc.daemon + `"}`))
					return
				}
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.container))
			})
			status, e := c.CheckSource(context.Background(), Source{"daemon", "source", "start"})
			if status != tc.want || tc.want == SourceUnknown && !errors.Is(e, ErrQuarantine) || tc.want != SourceUnknown && e != nil {
				t.Fatal(status, e)
			}
		})
	}
}
