package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinalizationFailureKeepsOwnedSnapshotUnknown(t *testing.T) {
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
	if strings.ContainsAny(binary, "'\n") {
		t.Fatal("invalid test binary path")
	}
	wrapper := filepath.Join(root, "fail-finalize")
	script := "#!/bin/sh\nif [ \"$2\" = tag ]; then exit 9; fi\nexec '" + binary + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	repo := Repository{Binary: wrapper, Env: env}
	helper, _ := os.Executable()
	meta := fileMetadata()
	meta.Paths[0] = "/database.dump"
	meta.Mounts[0].SnapshotPath = "/database.dump"
	result := repo.Backup(context.Background(), meta, "tag-error", "fixture", []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "success"})
	if result.Err == nil || result.Status != "unknown" || result.SnapshotID == "" {
		t.Fatalf("finalization error swallowed: %+v", result)
	}
	snapshots, err := repo.Snapshots(context.Background())
	if err != nil || len(snapshots) != 1 || snapshots[0].ID != result.SnapshotID || !hasTag(snapshots[0].Tags, "bakabel.status=unknown") {
		t.Fatalf("unknown snapshot lost: %+v %v", snapshots, err)
	}
	result = repo.Backup(context.Background(), meta, "tag-error", "fixture", nil)
	if result.Err == nil {
		t.Fatal("reused run identity accepted")
	}
	snapshots, err = repo.Snapshots(context.Background())
	if err != nil || len(snapshots) != 1 {
		t.Fatal("duplicate run changed repository")
	}
}
