package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestFilePreflightFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func() backup.Result
	}{
		{"worker_mount_guard", func() backup.Result {
			return backupFileTarget(context.Background(), nil, backup.Repository{}, workflowJob{}, docker.Target{})
		}},
		{"worker_protected_guard", func() backup.Result {
			return backupFileTarget(context.Background(), nil, backup.Repository{}, workflowJob{}, docker.Target{Mounts: []docker.Mount{{}}})
		}},
		{"adapter_metadata_guard", func() backup.Result {
			return files.Backup(context.Background(), backup.Repository{}, backup.Metadata{}, "run", "", nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.run()
			if res.Err == nil || res.Status != "unknown" {
				t.Fatalf("preflight semantics changed: %+v", res)
			}
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			var fields struct{ FailureStage string }
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if fields.FailureStage != "file_preflight" {
				t.Fatalf("stage = %q, want file_preflight", fields.FailureStage)
			}
		})
	}
}

func TestBackupTargetDiagnosticsSurviveReceipt(t *testing.T) {
	const canary = "credential-CANARY-do-not-export"
	dir := t.TempDir()
	binary := filepath.Join(dir, "restic")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' '"+canary+": no space left on device' >&2\nexit 3\n"), 0700); err != nil {
		t.Fatal(err)
	}
	commandErr := (backup.Repository{Binary: binary, Env: os.Environ()}).Dump(context.Background(), strings.Repeat("a", 64), "/dump", io.Discard)
	if commandErr == nil {
		t.Fatal("fixture did not fail")
	}
	for _, tc := range []struct {
		name string
		res  backup.Result
		want map[string]any
	}{
		{"joined_unknown", backup.Result{Status: "unknown", Err: errors.Join(commandErr, errors.New(canary)), FailureStage: "backup"}, map[string]any{"failureCode": "backup", "resticExitCode": float64(3), "resticReason": "enospc"}},
		{"partial", backup.Result{Status: "partial", SnapshotID: strings.Repeat("b", 64), Err: commandErr, FailureStage: "backup"}, map[string]any{"failureCode": "backup", "resticExitCode": float64(3), "resticReason": "enospc"}},
		{"metadata", backup.Result{Status: "unknown", Err: errors.New(canary), FailureStage: "metadata_readback"}, map[string]any{"failureCode": "metadata_readback"}},
		{"preflight", backup.Result{Status: "unknown", Err: errors.New(canary), FailureStage: "file_preflight"}, map[string]any{"failureCode": "file_preflight"}},
		{"complete_with_cleanup_error", backup.Result{Status: "complete", SnapshotID: strings.Repeat("b", 64), Err: errors.New(canary)}, map[string]any{}},
		{"complete", backup.Result{Status: "complete", SnapshotID: strings.Repeat("b", 64), FailureStage: canary}, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := backupTargetResult("source", tc.res)
			if tr.TargetID != "source" || tr.Status != tc.res.Status || tr.SnapshotID != tc.res.SnapshotID {
				t.Fatal("target identity/status changed")
			}
			wantError := "backup failed"
			if tc.res.Err == nil && tc.res.Status == "complete" {
				wantError = ""
			}
			if tr.Error != wantError {
				t.Fatalf("error = %q", tr.Error)
			}
			raw, err := json.Marshal(tr)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), canary) || strings.Contains(string(raw), "no space left on device") {
				t.Fatal("raw diagnostic escaped target JSON")
			}
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, field := range []string{"failureCode", "resticExitCode", "resticReason"} {
				if value, ok := wire[field]; ok {
					got[field] = value
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("diagnostic JSON = %v, want %v", got, tc.want)
			}
			cfg := config.Config{StateDir: t.TempDir()}
			if err := os.MkdirAll(filepath.Join(workflowDir(cfg), "output"), 0700); err != nil {
				t.Fatal(err)
			}
			j := workflowJob{RunID: strings.Repeat("a", 32), Targets: []docker.Target{{ID: "source", Kind: "volume"}}}
			status := "complete"
			if tr.Error != "" {
				status = "failed"
			}
			want := WorkflowResult{RunID: j.RunID, Status: status, Targets: []TargetResult{tr}}
			if err := publishJSON(filepath.Join(workflowDir(cfg), "output"), "result.json", want, maxWorkflowBytes); err != nil {
				t.Fatal(err)
			}
			gotReceipt, err := readWorkflowResult(cfg, j)
			if err != nil || !reflect.DeepEqual(gotReceipt, want) {
				t.Fatalf("receipt diagnostics/semantics changed: %+v %v", gotReceipt, err)
			}
		})
	}
}
