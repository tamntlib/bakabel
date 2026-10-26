package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestStreamDumpProducerCompletion(t *testing.T) {
	run := "bakabel_0123456789abcdef0123456789abcdef"
	payload := "PGDMPcomplete-archive-unit-payload"
	for _, tc := range []struct {
		name, trailer string
		exit          int
		ok, tamper    bool
	}{
		{"complete", "\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00", 0, true, false},
		{"frame_boundary_disconnect", "", 0, false, false},
		{"wrong_run", "\x00BAKABEL_EXPORT_COMPLETE_V1:wrong_run_0123456789abcdef\x00", 0, false, false},
		{"producer_failed", "\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00", 9, false, false},
		{"mismatched_exec_args", "\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg ExecConfig
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					w.Write([]byte(`{"ID":"daemon"}`))
				case "/v1.55/containers/source/json":
					w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
				case "/v1.55/containers/source/exec":
					if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
						t.Error(err)
					}
					w.Write([]byte(`{"Id":"dumpexec"}`))
				case "/v1.55/exec/dumpexec/json":
					args := append([]string(nil), cfg.Cmd[1:]...)
					if tc.tamper {
						args[len(args)-1] += "-changed"
					}
					json.NewEncoder(w).Encode(map[string]any{"ID": "dumpexec", "ContainerID": "source", "Running": false, "ExitCode": tc.exit, "ProcessConfig": map[string]any{"entrypoint": cfg.Cmd[0], "arguments": args}})
				case "/v1.55/exec/dumpexec/start":
					w.Write(append(frame(1, payload+tc.trailer), frame(2, "unit-private-diagnostic")...))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			defer c.Close()
			p := Postgres{Source: Source{DaemonID: "daemon", ContainerID: "source", StartedAt: "start"}, Database: "fixture", User: "postgres", prepared: true}
			d, err := c.CreateDump(context.Background(), p, run, func(Dump) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code, err := c.StreamDump(context.Background(), d, &out)
			if got := code == 0 && err == nil; got != tc.ok {
				t.Fatalf("export success=%v want=%v", got, tc.ok)
			}
			if tc.ok && out.String() != payload {
				t.Fatal("archive changed or protocol marker reached Restic")
			}
		})
	}
}
