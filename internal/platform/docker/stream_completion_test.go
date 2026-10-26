package docker

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

// A producer's terminal exit zero does not prove delivery of its entire output.
// This UNIT peer closes exactly between Docker frames, not inside a frame.
func TestStreamDumpRejectsUnprovenFrameBoundaryEOF(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
		case "/v1.55/exec/dumpexec/json":
			w.Write([]byte(`{"ID":"dumpexec","ContainerID":"source","Running":false,"ExitCode":0,"ProcessConfig":{"entrypoint":"/usr/local/bin/pg_dump"}}`))
		case "/v1.55/exec/dumpexec/start":
			w.Write(frame(1, "PGDMPprefix-with-missing-suffix"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer c.Close()
	d := Dump{Source: Source{DaemonID: "daemon", ContainerID: "source", StartedAt: "start"}, ExecID: "dumpexec", RunID: "bakabel_0123456789abcdef0123456789abcdef", Database: "fixture", User: "postgres"}
	var out bytes.Buffer
	if _, err := c.StreamDump(context.Background(), d, &out); err == nil {
		t.Fatal("unproven frame-boundary EOF accepted as complete export")
	}
}
