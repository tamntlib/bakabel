package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func frame(channel byte, b string) []byte {
	h := make([]byte, 8)
	h[0] = channel
	binary.BigEndian.PutUint32(h[4:], uint32(len(b)))
	return append(h, []byte(b)...)
}
func TestDemuxBoundedSeparated(t *testing.T) {
	var out, errout bytes.Buffer
	data := append(frame(1, strings.Repeat("a", 40000)), frame(2, "private diagnostic")...)
	if e := Demux(bytes.NewReader(data), &out, &errout); e != nil {
		t.Fatal(e)
	}
	if out.Len() != 40000 || errout.String() != "private diagnostic" {
		t.Fatal(out.Len(), errout.String())
	}
	for _, b := range [][]byte{{1}, frame(0, "x"), {1, 1, 0, 0, 0, 0, 0, 0}, {1, 0, 0, 0, 1, 0, 0, 1}, frame(1, "x")[:8]} {
		if e := Demux(bytes.NewReader(b), io.Discard, io.Discard); e == nil {
			t.Fatalf("bad frame accepted %v", b)
		}
	}
	if e := Demux(bytes.NewReader(frame(1, "data")), failWriter{}, io.Discard); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, errors.New("secret") }
func TestExecLifecycle(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/containers/source/exec":
			var x ExecConfig
			if e := json.NewDecoder(r.Body).Decode(&x); e != nil {
				t.Fatal(e)
			}
			if x.Tty || !x.AttachStdout || !x.AttachStderr || x.Cmd[0] != "fixed" {
				t.Error(x)
			}
			w.Write([]byte(`{"Id":"execid"}`))
		case "/v1.55/exec/execid/start":
			w.Write(append(frame(1, "dump"), frame(2, "warn")...))
		case "/v1.55/exec/execid/json":
			w.Write([]byte(`{"ID":"execid","ContainerID":"source","Running":false,"ExitCode":7}`))
		default:
			w.WriteHeader(404)
		}
	})
	ctx := context.Background()
	id, e := c.CreateExec(ctx, "source", ExecConfig{Cmd: []string{"fixed"}})
	if e != nil || id != "execid" {
		t.Fatal(id, e)
	}
	var out, errout bytes.Buffer
	if e = c.StartExec(ctx, id, &out, &errout); e != nil || out.String() != "dump" || errout.String() != "warn" {
		t.Fatal(out.String(), errout.String(), e)
	}
	s, e := c.PollExec(ctx, id)
	if e != nil || s.Running || s.ExitCode == nil || *s.ExitCode != 7 {
		t.Fatal(s, e)
	}
	code, e := c.WaitExec(ctx, id)
	if e != nil || code != 7 {
		t.Fatal(code, e)
	}
	if _, e = c.PollExec(ctx, "unknown"); !errors.Is(e, ErrQuarantine) {
		t.Fatal(e)
	}
}
func TestExecMissingExitQuarantine(t *testing.T) {
	for _, exit := range []string{"null", "-1", "256"} {
		t.Run(exit, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"ID":"execid","ContainerID":"source","Running":false,"ExitCode":` + exit + `}`))
			})
			if _, e := c.WaitExec(context.Background(), "execid"); !errors.Is(e, ErrQuarantine) {
				t.Fatal(e)
			}
		})
	}
}
