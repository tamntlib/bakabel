package backup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRetentionDisabledAndFailedRunNeverExecuteRestic(t *testing.T) {
	r := Repository{Binary: "/not-an-executable"}
	if err := r.Retain(context.Background(), Retention{}, "fixture", "compose", false); err != nil {
		t.Fatal("default retention is not off", err)
	}
	if err := r.Retain(context.Background(), Retention{Daily: 1}, "fixture", "compose", false); err == nil {
		t.Fatal("retention allowed after failed run")
	}
	if err := r.Retain(context.Background(), Retention{Daily: -1}, "fixture", "compose", true); err == nil {
		t.Fatal("negative retention accepted")
	}
}

func TestRealRetentionKeepsPartialUnknownAndScopesCompleteGroups(t *testing.T) {
	binary := os.Getenv("RESTIC_TEST_BINARY")
	if binary == "" {
		t.Skip("set RESTIC_TEST_BINARY for real repository test")
	}
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("fixture-only-password"), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "RESTIC_REPOSITORY="+filepath.Join(dir, "repo"), "RESTIC_PASSWORD_FILE="+password, "BAKABEL_SOURCE_FIXTURE=1", "GOMAXPROCS=2")
	cmd := exec.Command(binary, "--no-cache", "init")
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("init %v %s", err, out)
	}
	r := Repository{Binary: binary, Env: env}
	meta := fileMetadata()
	meta.Paths[0] = "/database.dump"
	meta.Mounts[0].SnapshotPath = meta.Paths[0]
	helper, _ := os.Executable()
	args := []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", helper, "-test.run=TestResticSourceHelper", "--", "success"}
	old := r.Backup(context.Background(), meta, "old-complete", "fixture", args)
	recent := r.Backup(context.Background(), meta, "recent-complete", "fixture", args)
	if old.Err != nil || recent.Err != nil {
		t.Fatal(old.Err, recent.Err)
	}
	unknownRepo := r
	unknownRepo.VerifySource = func(context.Context) error { return context.Canceled }
	unknown := unknownRepo.Backup(context.Background(), meta, "keep-unknown", "fixture", args)
	if unknown.Err == nil || unknown.SnapshotID == "" {
		t.Fatal("unknown fixture missing")
	}
	partial := r.Backup(context.Background(), meta, "keep-partial", "fixture", args)
	if partial.Err != nil {
		t.Fatal(partial.Err)
	}
	cmd = exec.Command(binary, "--no-cache", "tag", "--remove", "bakabel.status=complete", "--add", "bakabel.status=partial", partial.SnapshotID)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("partial fixture tag %v %s", err, out)
	}
	if err := r.Retain(context.Background(), Retention{Daily: 1}, "fixture", "compose", true); err != nil {
		t.Fatal(err)
	}
	snapshots, err := r.Snapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]bool{}
	for _, s := range snapshots {
		_, _, run, err := DecodeTags(s.Tags)
		if err != nil {
			t.Fatal(err)
		}
		runs[run] = true
	}
	if len(runs) != 3 || runs["old-complete"] || !runs["recent-complete"] || !runs["keep-unknown"] || !runs["keep-partial"] {
		t.Fatalf("retention deleted protected or retained wrong snapshot: %v", runs)
	}
	// Conflicting complete/unknown tags cannot be passed to native tag filters.
	cmd = exec.Command(binary, "--no-cache", "tag", "--add", "bakabel.status=unknown", recent.SnapshotID)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ambiguous fixture %v %s", err, out)
	}
	if err := r.Retain(context.Background(), Retention{Daily: 1}, "fixture", "compose", true); err == nil {
		t.Fatal("retention accepted ambiguous complete metadata")
	}
	after, err := r.Snapshots(context.Background())
	if err != nil || len(after) != len(snapshots) {
		t.Fatal("failed retention mutated snapshots", err)
	}
}
