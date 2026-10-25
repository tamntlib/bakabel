package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "engine.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	s := &http.Server{Handler: h}
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
	c, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestClientSourceIdentity(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon"})
		case "/v1.55/containers/source/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": "source", "State": map[string]any{"Running": true, "StartedAt": "incarnation"}})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	s, e := c.CaptureSource(context.Background(), "source")
	if e != nil {
		t.Fatal(e)
	}
	if s.ContainerID != "source" || s.StartedAt != "incarnation" || s.DaemonID != "daemon" {
		t.Fatal(s)
	}
	status, e := c.CheckSource(context.Background(), s)
	if e != nil || status != SourceRunning {
		t.Fatal(status, e)
	}
}
func TestSourceUnknownFailsClosed(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); w.Write([]byte("password=SECRET")) })
	_, e := c.CheckSource(context.Background(), Source{ContainerID: "source", DaemonID: "daemon", StartedAt: "start"})
	if !errors.Is(e, ErrQuarantine) || e.Error() == "password=SECRET" {
		t.Fatal(e)
	}
	if _, e = NewClient(""); e == nil {
		t.Fatal("empty socket accepted")
	}
}
