package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/state"
)

func healthConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: "/absent/docker.sock", StateDir: t.TempDir(), WorkerImage: "sha256:" + strings.Repeat("a", 64), Timeout: time.Minute, Schedule: "0 * * * *", Timezone: "UTC"}
}
func seedHealth(t *testing.T, c config.Config, r state.Result) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.StateDir, "last-result.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestHealthUsesLastBackupSuccessNotLatestRestore(t *testing.T) {
	c := healthConfig(t)
	at := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	seedHealth(t, c, state.Result{RunID: "restore", Status: state.OutcomeSuccess, Operation: "restore", FinishedAt: at.Add(10 * time.Minute).Format(time.RFC3339Nano), LastBackupSuccessAt: at.Format(time.RFC3339Nano)})
	got, err := Health(c, at.Add(30*time.Minute))
	if err != nil || got.Overdue || got.Status != "healthy" {
		t.Fatal(got, err)
	}
	got, err = Health(c, at.Add(time.Hour+time.Minute))
	if err == nil || !got.Overdue || got.Status != "overdue" {
		t.Fatal("restore reset backup freshness", got, err)
	}
	entries, _ := os.ReadDir(c.StateDir)
	if len(entries) != 1 {
		t.Fatal("health mutated state", entries)
	}
}
