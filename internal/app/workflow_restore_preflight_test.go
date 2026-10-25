package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestRestoreReadonlyPreflightFailureDoesNotCreateExecIntent(t *testing.T) {
	dir := t.TempDir()
	owner, err := state.Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	r := state.Record{RunID: strings.Repeat("a", 32), DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: state.PhaseIntent, Status: state.StatusActive}
	if err = owner.NewRun(r); err != nil {
		t.Fatal(err)
	}
	metadata := backup.Metadata{Version: 1, Kind: "postgres", Source: "source", Paths: []string{"/dump"}, Postgres: &backup.PostgresMetadata{Database: "fixture", ClusterID: "123", DatabaseOID: "456", ServerVersion: 180005, ClientVersion: 180005, Format: "custom", Owner: "owner", ACL: []backup.Grant{}}}
	tags, err := backup.EncodeTags(metadata, "complete", "previous")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := backup.Snapshot{ID: strings.Repeat("b", 64), Paths: metadata.Paths, Tags: tags}
	encoded, err := json.Marshal([]backup.Snapshot{snapshot})
	if err != nil {
		t.Fatal(err)
	}
	// Unit-only repository seam. There is no Docker socket, real repository or
	// import. Unsupported version must fail before any possible exec creation.
	program := filepath.Join(dir, "repo-fixture")
	if err = os.WriteFile(program, []byte("#!/bin/sh\nprintf '%s\\n' '"+string(encoded)+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	job := workflowJob{RunID: r.RunID, Restore: &RestoreRequest{SnapshotID: snapshot.ID, Database: "fixture", User: "postgres"}}
	target := docker.Target{ID: "source", Kind: "postgres", Source: docker.Source{DaemonID: "daemon", ContainerID: "target", StartedAt: "2026-01-01T00:00:00Z"}, Database: "fixture"}
	repository := backup.Repository{Binary: program}
	if _, err = exactSnapshot(context.Background(), repository, snapshot.ID); err != nil {
		t.Fatal("fixture did not reach version preflight", err)
	}
	result := restorePostgresTarget(context.Background(), owner, nil, repository, job, target)
	if result.Error == "" || result.Status == "restored" {
		t.Fatal("unsupported version unexpectedly restored", result)
	}
	got, err := owner.Load()
	if err != nil || got != r {
		t.Fatalf("read-only preflight created unrecoverable exec intent: got=%#v err=%v", got, err)
	}
}
