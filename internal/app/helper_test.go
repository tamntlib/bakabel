package app

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestExportRejectsUnpinnedOrArbitraryCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"run"}, {"_export"}, {"_export", "--cmd", "sh"}, {"_export", "--timeout", "0"}} {
		var out, err bytes.Buffer
		if Main(context.Background(), args, &out, &err) == 0 || out.Len() != 0 {
			t.Fatalf("accepted %q", args)
		}
	}
}

func TestExportAnyStreamErrorIsNonzero(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "docker.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "secret diagnostic", 500) })}
	go server.Serve(l)
	defer server.Close()
	var out, err bytes.Buffer
	args := []string{"_export", "--socket", socket, "--daemon", "daemon", "--container", "0123456789abcdef", "--started", "2026-10-25T00:00:00Z", "--exec", "0123456789abcdef", "--run", "bakabel_test_0123456789abcdef", "--database", "fixture", "--user", "postgres", "--timeout", "1s"}
	if Main(context.Background(), args, &out, &err) == 0 {
		t.Fatal("StreamDump error with code zero became helper success")
	}
	if bytes.Contains(err.Bytes(), []byte("secret")) || out.Len() != 0 {
		t.Fatal("diagnostic leaked")
	}
}
