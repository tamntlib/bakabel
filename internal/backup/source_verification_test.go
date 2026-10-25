package backup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceVerificationFailureLeavesSnapshotUnknown(t *testing.T) {
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
	verified := false
	repo := Repository{Binary: binary, Env: env, VerifySource: func(context.Context) error { verified = true; return errors.New("private-source-diagnostic") }}
	helper, _ := os.Executable()
	meta := fileMetadata()
	meta.Paths[0] = "/database.dump"
	meta.Mounts[0].SnapshotPath = "/database.dump"
	result := repo.Backup(context.Background(), meta, "source-changed", "fixture", []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "success"})
	if !verified || result.Err == nil || result.Status != "unknown" || result.SnapshotID == "" || strings.Contains(result.Err.Error(), "private-source-diagnostic") {
		t.Fatalf("verification failure ignored/leaked: %+v", result)
	}
	snapshots, err := repo.Snapshots(context.Background())
	if err != nil || len(snapshots) != 1 || !hasTag(snapshots[0].Tags, "bakabel.status=unknown") {
		t.Fatalf("source not verified but snapshot completed: %+v %v", snapshots, err)
	}
}
