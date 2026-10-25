package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestWorkflowReceiptValidatesMaintenanceSeparately(t *testing.T) {
	for _, tc := range []struct {
		name, status, maintenance string
		enabled, restore, valid   bool
	}{
		{"valid", "complete", "retention failed", true, false, true},
		{"arbitrary", "complete", "private endpoint error", true, false, false},
		{"failed data", "failed", "retention failed", true, false, false},
		{"disabled", "complete", "retention failed", false, false, false},
		{"restore", "restored", "retention failed", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := healthConfig(t)
			if tc.enabled {
				c.Retention = config.Retention{Daily: 1}
			}
			j := workflowJob{RunID: "run", Config: c, Targets: []docker.Target{{ID: "source", Kind: "postgres"}}}
			if tc.restore {
				j.Restore = &RestoreRequest{SnapshotID: strings.Repeat("a", 64)}
			}
			os.MkdirAll(filepath.Join(workflowDir(c), "output"), 0700)
			targetStatus := tc.status
			if targetStatus == "failed" {
				targetStatus = "unknown"
			}
			res := WorkflowResult{RunID: "run", Status: tc.status, MaintenanceError: tc.maintenance, Targets: []TargetResult{{TargetID: "source", Status: targetStatus, SnapshotID: strings.Repeat("a", 64)}}}
			if err := publishJSON(filepath.Join(workflowDir(c), "output"), "result.json", res, maxWorkflowBytes); err != nil {
				t.Fatal(err)
			}
			_, err := readWorkflowResult(c, j)
			if (err == nil) != tc.valid {
				t.Fatal(tc.name, err)
			}
		})
	}
}
