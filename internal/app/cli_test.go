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
	"testing"
)

func TestCLIPlanReadOnlyNoTargets(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "docker.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	var writes int
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
			t.Errorf("plan wrote %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1.55/info":
			fmt.Fprint(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/json":
			fmt.Fprint(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(listener)
	defer srv.Close()
	path := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf("version: 1\ninstallation: fixture\nplatform: compose\nscope: [fixture]\nrepository: /repository\ncredentials:\n  password_file: /password\ndocker_socket: %s\nstate_dir: %s\nworker_image: sha256:%s\n", socket, filepath.Join(dir, "must-not-exist"), strings.Repeat("a", 64))
	if e = os.WriteFile(path, []byte(cfg), 0600); e != nil {
		t.Fatal(e)
	}
	var out, err bytes.Buffer
	code := Main(context.Background(), []string{"--config", path, "plan"}, &out, &err)
	if code != 0 || !strings.Contains(out.String(), `"targets":[]`) {
		t.Fatalf("code=%d out=%s err=%s", code, &out, &err)
	}
	if writes != 0 {
		t.Fatal(writes)
	}
	if _, e = os.Stat(filepath.Join(dir, "must-not-exist")); !os.IsNotExist(e) {
		t.Fatal("plan initialized state", e)
	}
}

func TestCLIRejectsExtraOrUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"plan"}, {"--config"}, {"--config", "no-file", "run", "extra"}, {"--config", "no-file", "restore", "--force"}} {
		var out, err bytes.Buffer
		if Main(context.Background(), args, &out, &err) == 0 || out.Len() != 0 {
			t.Fatal(args, &out, &err)
		}
	}
}
