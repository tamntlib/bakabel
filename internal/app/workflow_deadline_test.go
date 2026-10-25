package app

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunBoundsPreWorkerDockerDiscovery(t *testing.T) {
	c := healthConfig(t)
	c.Timeout = 20 * time.Millisecond
	c.DockerSocket = filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", c.DockerSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})}
	go server.Serve(ln)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = Run(ctx, c)
	if err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatal("configured deadline did not bound discovery", time.Since(start), err)
	}
	entries, _ := os.ReadDir(c.StateDir)
	if len(entries) != 0 {
		t.Fatal("timed-out preflight mutated state")
	}
}
