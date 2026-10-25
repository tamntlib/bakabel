package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestWorkflowReceiptKeepsSnapshotIDAndFixedError(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{StateDir: dir}
	os.Mkdir(workflowDir(c), 0700)
	os.Mkdir(filepath.Join(workflowDir(c), "output"), 0700)
	j := workflowJob{RunID: strings.Repeat("a", 32), Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	want := WorkflowResult{RunID: j.RunID, Status: "failed", Targets: []TargetResult{{TargetID: "source", Status: "complete", SnapshotID: strings.Repeat("b", 64), Error: "backup failed"}}}
	if e := publishJSON(filepath.Join(workflowDir(c), "output"), "result.json", want, maxWorkflowBytes); e != nil {
		t.Fatal(e)
	}
	got, e := readWorkflowResult(c, j)
	if e != nil || len(got.Targets) != 1 || got.Targets[0] != want.Targets[0] {
		t.Fatal("lost snapshot ID or fixed error", got, e)
	}
}

func TestWorkflowReceiptRejectsRestoreStatusOnBackupRun(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{StateDir: dir}
	os.Mkdir(workflowDir(c), 0700)
	os.Mkdir(filepath.Join(workflowDir(c), "output"), 0700)
	j := workflowJob{RunID: strings.Repeat("a", 32), Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	wrong := WorkflowResult{RunID: j.RunID, Status: "restored", Targets: []TargetResult{{TargetID: "source", Status: "restored", SnapshotID: strings.Repeat("b", 64)}}}
	if e := publishJSON(filepath.Join(workflowDir(c), "output"), "result.json", wrong, maxWorkflowBytes); e != nil {
		t.Fatal(e)
	}
	if _, e := readWorkflowResult(c, j); e == nil {
		t.Fatal("cross-mode success receipt accepted")
	}
}

func TestDescribeSnapshotCannotClaimCompleteWithWrongLayout(t *testing.T) {
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: "fixture", Paths: []string{"/dump"}, Postgres: &backup.PostgresMetadata{Database: "db", ClusterID: "1", DatabaseOID: "2", ServerVersion: 180006, ClientVersion: 180006, Owner: "postgres", Format: "custom", ACL: []backup.Grant{}}}
	tags, e := backup.EncodeTags(m, "complete", "run")
	if e != nil {
		t.Fatal(e)
	}
	s := backup.Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: []string{"/wrong"}}
	if row := describeSnapshot(s); row.Status == "complete" {
		t.Fatal("wrong layout advertised as complete", row)
	}
}

func TestWorkflowJobRejectsFutureClockOrInvalidRunToken(t *testing.T) {
	j := workflowJob{Version: 1, RunID: strings.Repeat("a", 32), CreatedAt: time.Now(), Config: config.Config{Version: 1, Installation: "fixture", Platform: "compose", Scope: []string{"fixture"}, Repository: "/repository", Credentials: config.Credentials{PasswordFile: "/password"}, DockerSocket: "/docker.sock", StateDir: "/state", WorkerImage: "sha256:" + strings.Repeat("a", 64), Timeout: time.Minute, Timezone: "UTC"}, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
	if validateWorkflowJob(j) != nil {
		t.Fatal("valid bounded job refused")
	}
	j.RunID = strings.Repeat("z", 32)
	if validateWorkflowJob(j) == nil {
		t.Fatal("invalid run token accepted")
	}
	j.RunID = strings.Repeat("a", 32)
	j.CreatedAt = time.Now().Add(time.Hour)
	if validateWorkflowJob(j) == nil {
		t.Fatal("future deadline extension accepted")
	}
	j.CreatedAt = time.Now()
	j.Config.Timeout = 25 * time.Hour
	if validateWorkflowJob(j) != nil {
		t.Fatal("validated configurable timeout was narrowed by legacy B1 limit")
	}
}
