package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestCancelExactIdentityAndSessionProof(t *testing.T) {
	signaled := false
	scans := 0
	sessions := false
	var cfg ExecConfig
	d := Dump{Source: Source{"daemon", "source", "start"}, ExecID: "dumpexec", RunID: "bakabel_0123456789abcdef0123456789abcdef", Database: "fixture", User: "postgres"}
	argv, err := legacyDumpCommand(d)
	if err != nil {
		t.Fatal(err)
	}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
		case "/v1.55/exec/dumpexec/json":
			json.NewEncoder(w).Encode(map[string]any{"ID": "dumpexec", "ContainerID": "source", "Running": !signaled, "ExitCode": 1, "ProcessConfig": map[string]any{"entrypoint": argv[0], "arguments": argv[1:]}})
		case "/v1.55/containers/source/exec":
			json.NewDecoder(r.Body).Decode(&cfg)
			w.Write([]byte(`{"Id":"control"}`))
		case "/v1.55/exec/control/start":
			switch {
			case cfg.Cmd[0] == "psql":
				sessions = true
				if !strings.Contains(cfg.Cmd[len(cfg.Cmd)-1], "pg_stat_activity") {
					t.Error(cfg)
				}
				w.Write(frame(1, "0\n"))
			case strings.Contains(cfg.Cmd[2], "STARTTIME_MISMATCH"):
				args := cfg.Cmd[len(cfg.Cmd)-4:]
				if strings.Join(args, "|") != "123|777|bakabel_0123456789abcdef0123456789abcdef|TERM" {
					t.Error(args)
				}
				signaled = true
			default:
				scans++
				if !signaled {
					w.Write(frame(1, "123|777|/usr/local/bin/pg_dump\n"))
				}
			}
		case "/v1.55/exec/control/json":
			w.Write([]byte(`{"ID":"control","ContainerID":"source","Running":false,"ExitCode":0}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	})
	proof, e := c.CancelDump(context.Background(), d)
	if e != nil || !proof.NoProcesses || !proof.NoSessions || proof.ExecExitCode == nil || *proof.ExecExitCode != 1 || !signaled || scans != 2 || !sessions {
		t.Fatal(proof, e, scans, sessions)
	}
}
func TestCancelUnknownExecQuarantines(t *testing.T) {
	controls := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
		default:
			controls++
			w.WriteHeader(404)
		}
	})
	_, e := c.CancelDump(context.Background(), Dump{Source: Source{"daemon", "source", "start"}, ExecID: "unknown", RunID: "bakabel_0123456789abcdef0123456789abcdef", Database: "fixture", User: "postgres"})
	if !errors.Is(e, ErrQuarantine) || controls != 1 {
		t.Fatal(e, controls)
	}
}
