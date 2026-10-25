package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResticNeverFinalizesWrongLayout(t *testing.T) {
	binary := os.Getenv("RESTIC_TEST_BINARY")
	if binary == "" {
		t.Skip("set RESTIC_TEST_BINARY for real repository test")
	}
	root := t.TempDir()
	password := filepath.Join(root, "password")
	if err := os.WriteFile(password, []byte("fixture-only-password"), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "RESTIC_REPOSITORY="+filepath.Join(root, "repo"), "RESTIC_PASSWORD_FILE="+password, "BAKABEL_SOURCE_FIXTURE=1", "GOMAXPROCS=2")
	init := exec.Command(binary, "--no-cache", "init")
	init.Env = env
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init %v %s", err, out)
	}
	repo := Repository{Binary: binary, Env: env}
	helper, _ := os.Executable()
	result := repo.Backup(context.Background(), fileMetadata(), "wrong-layout", "fixture", []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "success"})
	if result.Err == nil || result.Status != "unknown" || result.SnapshotID == "" {
		t.Fatalf("mismatched snapshot layout accepted: %+v", result)
	}
	snapshots, err := repo.Snapshots(context.Background())
	if err != nil || len(snapshots) != 1 || !hasTag(snapshots[0].Tags, "bakabel.status=unknown") {
		t.Fatalf("mismatched layout finalized: %+v %v", snapshots, err)
	}
}
