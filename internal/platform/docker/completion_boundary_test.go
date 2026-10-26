package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestStreamDumpCompleteVersusSuffixLoss(t *testing.T) {
	d := Dump{Source: Source{"daemon", "source", "start"}, ExecID: "dumpexec", RunID: "bakabel_0123456789abcdef0123456789abcdef", Database: "fixture", User: "postgres"}
	argv, err := dumpCommand(d)
	if err != nil {
		t.Fatal(err)
	}
	payload := "PGDMP" + strings.Repeat("x", 40960-5)
	marker := "\x00BAKABEL_EXPORT_COMPLETE_V1:" + d.RunID + "\x00"
	for _, tc := range []struct {
		name, wire string
		ok         bool
	}{
		{"full", string(frame(1, payload+marker)), true},
		{"boundary_drop", string(frame(1, payload[:32768])), false},
		{"midframe_drop", string(frame(1, payload)[:8+32768]), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					fmt.Fprint(w, `{"ID":"daemon"}`)
				case "/v1.55/containers/source/json":
					fmt.Fprint(w, `{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`)
				case "/v1.55/exec/dumpexec/json":
					json.NewEncoder(w).Encode(map[string]any{"ID": d.ExecID, "ContainerID": d.Source.ContainerID, "Running": false, "ExitCode": 0, "ProcessConfig": map[string]any{"entrypoint": argv[0], "arguments": argv[1:]}})
				case "/v1.55/exec/dumpexec/start":
					fmt.Fprint(w, tc.wire)
				default:
					w.WriteHeader(404)
				}
			})
			defer c.Close()
			var out bytes.Buffer
			code, err := c.StreamDump(context.Background(), d, &out)
			if got := err == nil && code == 0; got != tc.ok {
				t.Fatalf("success=%v want=%v", got, tc.ok)
			}
			if tc.ok && out.String() != payload {
				t.Fatal("full archive bytes not preserved")
			}
		})
	}
}

func TestDumpCompletionEverySuffixCutAndSplit(t *testing.T) {
	run := "bakabel_0123456789abcdef0123456789abcdef"
	payload := []byte("PGDMP" + strings.Repeat("x", 100))
	marker := []byte("\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00")
	wire := append(append([]byte(nil), payload...), marker...)
	for cut := 0; cut < len(wire); cut++ {
		s := newDumpStream(&bytes.Buffer{}, run)
		if _, err := s.Write(wire[:cut]); err != nil {
			t.Fatal(err)
		}
		if s.Finish() == nil {
			t.Fatalf("proper prefix accepted at %d", cut)
		}
	}
	for split := 0; split <= len(wire); split++ {
		var out bytes.Buffer
		s := newDumpStream(&out, run)
		for _, part := range [][]byte{wire[:split], wire[split:]} {
			if _, err := s.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Finish(); err != nil || !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("complete split %d rejected: %v", split, err)
		}
	}
}
