package restic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/state"
)

func resticBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("RESTIC_BIN"); p != "" {
		return p
	}
	p, err := exec.LookPath("restic")
	if err != nil {
		t.Skip("restic binary not installed in PATH")
	}
	return p
}

func TestIsMissingRepoErrorClassification(t *testing.T) {
	if !isMissingRepoError("Fatal: unable to open config file: stat /repo/config: no such file or directory\nIs there a repository at the following location?") {
		t.Fatal("expected missing repo to match")
	}
	if isMissingRepoError("Fatal: wrong password or no key found") {
		t.Fatal("wrong password must never classify as missing repo")
	}
	if isMissingRepoError("Fatal: unable to open config file: 403 Forbidden") {
		t.Fatal("403 Forbidden must never classify as missing repo")
	}
}

func TestEnsureRepoAutoInitAndGuards(t *testing.T) {
	bin := resticBin(t)
	ctx := context.Background()
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	st := state.New(filepath.Join(dir, "state"))

	cfg := config.Config{
		Repository:     repo,
		ResticPassword: "test-password-123",
		ResticBin:      bin,
		ResticCacheDir: filepath.Join(dir, "cache"),
		AutoInit:       true,
	}
	rc := New(cfg)

	// 1. First run on empty/non-existent dir auto-initializes and pins repo_id.
	repoID, inited, err := rc.EnsureRepo(ctx, st)
	if err != nil || !inited || repoID == "" {
		t.Fatalf("first EnsureRepo = (%q, %v, %v), want initialized", repoID, inited, err)
	}

	// 2. Second run reuses existing repo without re-initializing.
	repoID2, inited2, err := rc.EnsureRepo(ctx, st)
	if err != nil || inited2 || repoID2 != repoID {
		t.Fatalf("second EnsureRepo = (%q, %v, %v), want reuse %q", repoID2, inited2, err, repoID)
	}

	// 3. Wrong password must fail closed (never auto-init).
	badPassCfg := cfg
	badPassCfg.ResticPassword = "wrong-password"
	if _, _, err := New(badPassCfg).EnsureRepo(ctx, st); err == nil {
		t.Fatal("expected wrong password to fail")
	}

	// 4. If repo disappears while state still pins repoID, refuse auto-init!
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rc.EnsureRepo(ctx, st); err == nil || !strings.Contains(err.Error(), "refusing to auto-initialize") {
		t.Fatalf("expected refusal when state already pins repo_id, got: %v", err)
	}

	// 5. Fresh state + non-empty directory must refuse auto-init!
	nonEmpty := filepath.Join(dir, "nonempty")
	_ = os.MkdirAll(nonEmpty, 0o700)
	_ = os.WriteFile(filepath.Join(nonEmpty, "unrelated.txt"), []byte("keep"), 0o600)
	nonEmptyCfg := cfg
	nonEmptyCfg.Repository = nonEmpty
	if _, _, err := New(nonEmptyCfg).EnsureRepo(ctx, state.New(filepath.Join(dir, "state2"))); err == nil || !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("expected refusal on non-empty dir, got: %v", err)
	}
}

func TestBackupStdinDumpSnapshotsAndRetention(t *testing.T) {
	bin := resticBin(t)
	ctx := context.Background()
	dir := t.TempDir()
	st := state.New(filepath.Join(dir, "state"))
	rc := New(config.Config{
		Repository:     filepath.Join(dir, "repo"),
		ResticPassword: "test-password-123",
		ResticBin:      bin,
		ResticCacheDir: filepath.Join(dir, "cache"),
		AutoInit:       true,
	})
	if _, _, err := rc.EnsureRepo(ctx, st); err != nil {
		t.Fatalf("EnsureRepo: %v", err)
	}

	tags := []string{"bakabel", "type:postgres", "stack:app", "service:db", "target:app/db/postgres/mydb"}
	snapID, err := rc.BackupStdin(ctx, "mydb.dump", "bakabel", tags, strings.NewReader("PGDMP-payload-1"))
	if err != nil || snapID == "" {
		t.Fatalf("BackupStdin: %q, %v", snapID, err)
	}

	snaps, err := rc.Snapshots(ctx)
	if err != nil || len(snaps) != 1 || snaps[0].ID != snapID {
		t.Fatalf("Snapshots = %+v, %v", snaps, err)
	}

	dump, err := rc.Dump(ctx, snapID, "/mydb.dump")
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	var got strings.Builder
	buf := make([]byte, 64)
	for {
		n, rErr := dump.Reader.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if rErr != nil {
			break
		}
	}
	_ = dump.Reader.Close()
	if err := dump.Wait(); err != nil {
		t.Fatalf("Dump.Wait: %v", err)
	}
	if got.String() != "PGDMP-payload-1" {
		t.Fatalf("restored dump = %q", got.String())
	}

	if err := rc.ForgetPrune(ctx, config.Retention{Last: 1}); err != nil {
		t.Fatalf("ForgetPrune: %v", err)
	}
}
