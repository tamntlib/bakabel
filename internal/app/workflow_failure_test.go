package app

import (
	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"strings"
	"testing"
)

func TestMissingReceiptRecoversExactRepositoryIDWithError(t *testing.T) {
	j := workflowJob{RunID: strings.Repeat("a", 32), Targets: []docker.Target{{ID: "first", Kind: "postgres"}}}
	j.Config.Installation = "fixture"
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: "first", Paths: []string{postgresPath("first")}, Postgres: &backup.PostgresMetadata{Database: "db", ClusterID: "1", DatabaseOID: "2", ServerVersion: 180006, ClientVersion: 180006, Owner: "postgres", Format: "custom", ACL: []backup.Grant{}}}
	tags, e := backup.EncodeTags(m, "unknown", j.RunID+"-"+targetHash("first"))
	if e != nil {
		t.Fatal(e)
	}
	snap := backup.Snapshot{ID: strings.Repeat("b", 64), Hostname: files.Hostname("fixture"), Tags: tags, Paths: m.Paths}
	got := recoverFailureSnapshots(j, failedWorkflow(j), []backup.Snapshot{snap})
	if got.Status != "failed" || got.Targets[0].SnapshotID != snap.ID || got.Targets[0].Error != "backup failed" || got.Targets[0].Status != "unknown" {
		t.Fatal(got)
	}
	other := snap
	other.ID = strings.Repeat("c", 64)
	got = recoverFailureSnapshots(j, failedWorkflow(j), []backup.Snapshot{snap, other})
	if got.Targets[0].SnapshotID != "" {
		t.Fatal("ambiguous snapshot identity adopted", got)
	}
}

func TestMissingReceiptStillReportsEveryFrozenTarget(t *testing.T) {
	j := workflowJob{RunID: strings.Repeat("a", 32), Targets: []docker.Target{{ID: "first"}, {ID: "second"}}}
	r := failedWorkflow(j)
	if r.RunID != j.RunID || r.Status != "failed" || len(r.Targets) != 2 {
		t.Fatal(r)
	}
	for i, tr := range r.Targets {
		if tr.TargetID != j.Targets[i].ID || tr.SnapshotID != "" || tr.Status != "unknown" || tr.Error != "backup failed" {
			t.Fatal(tr)
		}
	}
}
