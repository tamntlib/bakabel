package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlanClosesOwnedDockerIdleConnections(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var live, opened atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/json":
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}), ConnState: func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
			live.Add(1)
		}
		if s == http.StateClosed {
			live.Add(-1)
		}
	}}
	go server.Serve(listener)
	defer server.Close()
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("version: 1\ninstallation: fixture\nplatform: compose\nscope: [fixture]\nrepository: /repository\ncredentials:\n  password_file: /password\ndocker_socket: %s\nstate_dir: %s\nworker_image: sha256:%s\ntimeout: 5s\n", socket, dir, strings.Repeat("a", 64))
	if err = os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := publicMain(context.Background(), []string{"--config", path, "plan"}, &stdout, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if opened.Load() == 0 {
		t.Fatal("fixture never established an HTTP connection")
	}
	deadline := time.Now().Add(time.Second)
	for live.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if live.Load() != 0 {
		t.Fatalf("completed command retained %d idle Docker connections", live.Load())
	}
}
