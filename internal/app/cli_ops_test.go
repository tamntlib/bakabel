package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/state"
	"gopkg.in/yaml.v3"
)

func TestPublicHealthAndServeCommands(t *testing.T) {
	c := healthConfig(t)
	seedHealth(t, c, state.Result{RunID: "run", Status: state.OutcomeSuccess, Operation: "backup", LastBackupSuccessAt: time.Now().UTC().Format(time.RFC3339Nano)})
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if code := Main(context.Background(), []string{"--config", p, "health"}, &out, &diagnostics); code != 0 {
		t.Fatal(code, out.String(), diagnostics.String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Main(ctx, []string{"--config", p, "serve"}, &out, &diagnostics); code != 0 {
		t.Fatal("normal serve shutdown", code, diagnostics.String())
	}
	for _, command := range []string{"serve", "health"} {
		if code := Main(ctx, []string{"--config", p, command, "unexpected"}, &out, &diagnostics); code == 0 {
			t.Fatal("accepted unsupported arguments", command)
		}
	}
}
