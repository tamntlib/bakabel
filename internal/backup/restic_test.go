package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResticSourceHelper(t *testing.T) {
	if os.Getenv("BAKABEL_SOURCE_FIXTURE") != "1" {
		return
	}
	fmt.Print(strings.Repeat("backup-fixture", 4096))
	if os.Args[len(os.Args)-1] == "fail" {
		os.Exit(7)
	}
	os.Exit(0)
}

func TestResticStreamingFailureAndExactFinalization(t *testing.T) {
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
		t.Fatalf("init: %v %s", err, out)
	}
	repo := Repository{Binary: binary, Env: env}
	meta := fileMetadata()
	meta.Paths[0] = "/database.dump"
	meta.Mounts[0].SnapshotPath = "/database.dump"
	helper, _ := os.Executable()
	failed := repo.Backup(context.Background(), meta, "failed", "fixture", []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "fail"})
	if failed.Err == nil || failed.Status == "complete" {
		t.Fatalf("producer failure swallowed: %+v", failed)
	}
	list, err := repo.Snapshots(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("failed producer snapshot: %v %v", list, err)
	}
	good := repo.Backup(context.Background(), meta, "success", "fixture", []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "success"})
	if good.Err != nil || good.Status != "complete" || len(good.SnapshotID) != 64 {
		t.Fatalf("backup: %+v", good)
	}
	list, err = repo.Snapshots(context.Background())
	if err != nil || len(list) != 1 || list[0].ID != good.SnapshotID {
		t.Fatalf("readback mismatch: %v %v", list, err)
	}
	var restored strings.Builder
	if err := repo.Dump(context.Background(), good.SnapshotID, "database.dump", &restored); err != nil {
		t.Fatal(err)
	}
	if restored.String() != strings.Repeat("backup-fixture", 4096) {
		t.Fatal("restore content differs")
	}
}
