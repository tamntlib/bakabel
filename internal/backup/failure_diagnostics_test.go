package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only the fixed diagnostic interface is observable, never the child's stderr.
type commandDiagnostic interface {
	error
	ExitCode() int
	Reason() string
}

func TestCommandFailureDiagnosticsAreBoundedAndSafe(t *testing.T) {
	const canary = "credential-CANARY-do-not-export"
	for _, tc := range []struct {
		name, stderr, reason string
		exit                 int
	}{
		{"space", canary + ": no space left on device", "enospc", 1},
		{"permission", canary + ": Permission denied", "permission", 3},
		{"backend", canary + ": connection refused", "backend", 10},
		{"unknown", canary, "unknown", 1},
		{"missing", "", "unknown", 137},
		{"not_oom_proof", canary + ": killed OOM", "unknown", 137},
		{"bounded", strings.Repeat("x", 64*1024) + canary + ": no space left on device", "unknown", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stderr := filepath.Join(dir, "stderr")
			if err := os.WriteFile(stderr, []byte(tc.stderr), 0600); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(dir, "restic")
			if err := os.WriteFile(script, []byte(fmt.Sprintf("#!/bin/sh\ncat \"$DIAGNOSTIC_STDERR\" >&2\nexit %d\n", tc.exit)), 0700); err != nil {
				t.Fatal(err)
			}
			err := (Repository{Binary: script, Env: append(os.Environ(), "DIAGNOSTIC_STDERR="+stderr)}).command(context.Background(), io.Discard, "backup")
			if err == nil || err.Error() != fmt.Sprintf("restic failed (exit %d)", tc.exit) {
				t.Fatalf("unsafe or changed command error: %v", err)
			}
			var diagnostic commandDiagnostic
			if !errors.As(errors.Join(errors.New("safe wrapper"), err), &diagnostic) {
				t.Fatal("command failure has no typed safe diagnostics")
			}
			if diagnostic.ExitCode() != tc.exit || diagnostic.Reason() != tc.reason {
				t.Fatalf("diagnostics: exit=%d reason=%q", diagnostic.ExitCode(), diagnostic.Reason())
			}
			for _, output := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", diagnostic)} {
				if strings.Contains(output, canary) || strings.Contains(output, "no space left on device") {
					t.Fatal("raw stderr escaped command error")
				}
			}
		})
	}
}

func TestBackupFailureStageSurvivesFinalization(t *testing.T) {
	for _, tc := range []struct {
		name, failAt, stage, status string
		backupFails, sourceFails    bool
		exit                        int
	}{
		{name: "complete", status: "complete"},
		{name: "list_before", failAt: "list_before", stage: "list_before", status: "unknown", exit: 9},
		{name: "invalid_initial_json", failAt: "invalid_initial_json", stage: "metadata_readback", status: "unknown"},
		{name: "backup_then_successful_readback", backupFails: true, stage: "backup", status: "partial", exit: 3},
		{name: "list_after", failAt: "list_after", stage: "list_after", status: "unknown", exit: 9},
		{name: "invalid_post_backup_json", failAt: "invalid_post_backup_json", stage: "metadata_readback", status: "unknown"},
		{name: "source_verification", sourceFails: true, stage: "source_verification", status: "unknown"},
		{name: "tag", failAt: "tag", stage: "tag", status: "unknown", exit: 9},
		{name: "final_readback", failAt: "final_readback", stage: "final_readback", status: "unknown", exit: 9},
		{name: "invalid_final_json", failAt: "invalid_final_json", stage: "metadata_readback", status: "unknown"},
		{name: "metadata_readback", failAt: "metadata_readback", stage: "metadata_readback", status: "unknown"},
		{name: "final_metadata_readback", failAt: "final_metadata_readback", stage: "metadata_readback", status: "unknown"},
		{name: "backup_then_list_failure", backupFails: true, failAt: "list_after", stage: "backup", status: "unknown", exit: 3},
		{name: "backup_then_tag_failure", backupFails: true, failAt: "tag", stage: "backup", status: "unknown", exit: 3},
		{name: "backup_then_final_failure", backupFails: true, failAt: "final_readback", stage: "backup", status: "unknown", exit: 3},
		{name: "backup_then_metadata_failure", backupFails: true, failAt: "metadata_readback", stage: "backup", status: "unknown", exit: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			meta := fileMetadata()
			for _, status := range []string{"unknown", "complete", "partial"} {
				tags, err := EncodeTags(meta, status, "diagnostic-run")
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal([]Snapshot{{ID: strings.Repeat("a", 64), Tags: tags, Paths: meta.Paths, Hostname: "fixture"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, status), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := `#!/bin/sh
cd "$DIAGNOSTIC_DIR" || exit 99
fail() { printf '%s\n' 'credential-CANARY-do-not-export: connection refused' >&2; exit 9; }
case "$2" in
snapshots)
 n=0; if [ -f count ]; then read -r n < count; fi
 n=$((n+1)); printf '%s\n' "$n" > count
 case "$n" in
 1) [ "$FAIL_AT" = list_before ] && fail
    if [ "$FAIL_AT" = invalid_initial_json ]; then printf 'invalid'; else printf '[]'; fi;;
 2) [ "$FAIL_AT" = list_after ] && fail
    if [ "$FAIL_AT" = invalid_post_backup_json ]; then printf 'invalid'
    elif [ "$FAIL_AT" = metadata_readback ]; then printf '[]'; else cat unknown; fi;;
 3) [ "$FAIL_AT" = final_readback ] && fail
    if [ "$FAIL_AT" = invalid_final_json ]; then printf 'invalid'
    elif [ "$FAIL_AT" = final_metadata_readback ]; then cat unknown
    elif [ "$FAIL_BACKUP" = true ]; then cat partial; else cat complete; fi;;
 *) exit 98;;
 esac;;
backup)
 if [ "$FAIL_BACKUP" = true ]; then printf '%s\n' 'credential-CANARY-do-not-export: permission denied' >&2; exit 3; fi;;
tag) [ "$FAIL_AT" = tag ] && fail;;
*) exit 97;;
esac
exit 0
`
			binary := filepath.Join(dir, "restic")
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			r := Repository{Binary: binary, Env: append(os.Environ(), "DIAGNOSTIC_DIR="+dir, "FAIL_AT="+tc.failAt, fmt.Sprintf("FAIL_BACKUP=%t", tc.backupFails))}
			if tc.sourceFails {
				r.VerifySource = func(context.Context) error { return errors.New("credential-CANARY-do-not-export") }
			}
			result := r.Backup(context.Background(), meta, "diagnostic-run", "fixture", nil)
			// Encoding lets the missing field fail behaviorally in the RED run.
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			var stage string
			if value, ok := fields["FailureStage"]; ok {
				if err := json.Unmarshal(value, &stage); err != nil {
					t.Fatal(err)
				}
			}
			if stage != tc.stage {
				t.Fatalf("failure stage = %q, want %q", stage, tc.stage)
			}
			if result.Status != tc.status || (result.Err != nil) != (tc.stage != "") {
				t.Fatalf("changed backup semantics: %+v", result)
			}
			var diagnostic *CommandError
			if tc.exit != 0 {
				if !errors.As(result.Err, &diagnostic) || diagnostic.ExitCode() != tc.exit {
					t.Fatalf("lost command exit: %v", result.Err)
				}
				wantReason := "backend"
				if tc.backupFails {
					wantReason = "permission"
				}
				if diagnostic.Reason() != wantReason {
					t.Fatalf("reason = %q", diagnostic.Reason())
				}
			} else if errors.As(result.Err, &diagnostic) {
				t.Fatal("manufactured command diagnostic")
			}
			if strings.Contains(string(raw)+fmt.Sprintf("%+v", result.Err), "credential-CANARY-do-not-export") {
				t.Fatal("raw diagnostic escaped backup result")
			}
		})
	}
}
