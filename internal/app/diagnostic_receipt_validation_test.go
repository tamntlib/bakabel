package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestSignaledResticDoesNotInventAnExitStatus(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "restic")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nkill -KILL $$\n"), 0700); err != nil {
		t.Fatal(err)
	}
	err := (backup.Repository{Binary: binary, Env: os.Environ()}).Dump(context.Background(), strings.Repeat("a", 64), "/dump", io.Discard)
	if err == nil {
		t.Fatal("fixture did not terminate by signal")
	}
	tr := backupTargetResult("source", backup.Result{Status: "unknown", Err: err, FailureStage: "backup"})
	if tr.ResticExitCode != nil || tr.ResticReason != "unknown" {
		t.Fatalf("signaled child invented exit status or cause: %+v", tr)
	}
}

func TestReceiptRejectsNonFiniteBackupDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*TargetResult)
	}{
		{"stage", func(tr *TargetResult) { tr.FailureCode = "private-CANARY-stage" }},
		{"reason", func(tr *TargetResult) { tr.ResticReason = "private-CANARY-stderr" }},
		{"negative_exit", func(tr *TargetResult) { value := -1; tr.ResticExitCode = &value }},
		{"large_exit", func(tr *TargetResult) { value := 256; tr.ResticExitCode = &value }},
		{"successful_target", func(tr *TargetResult) {
			tr.Error = ""
			tr.Status = "complete"
			tr.SnapshotID = strings.Repeat("a", 64)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{StateDir: t.TempDir()}
			if err := os.MkdirAll(filepath.Join(workflowDir(cfg), "output"), 0700); err != nil {
				t.Fatal(err)
			}
			j := workflowJob{RunID: strings.Repeat("b", 32), Targets: []docker.Target{{ID: "source", Kind: "volume"}}}
			tr := TargetResult{TargetID: "source", Status: "unknown", Error: "backup failed", FailureCode: "backup", ResticReason: "unknown"}
			tc.edit(&tr)
			status := "failed"
			if tr.Error == "" {
				status = "complete"
			}
			res := WorkflowResult{RunID: j.RunID, Status: status, Targets: []TargetResult{tr}}
			if err := publishJSON(filepath.Join(workflowDir(cfg), "output"), "result.json", res, maxWorkflowBytes); err != nil {
				t.Fatal(err)
			}
			if _, err := readWorkflowResult(cfg, j); err == nil {
				t.Fatal("non-finite or misplaced diagnostics accepted from receipt")
			}
		})
	}
}
