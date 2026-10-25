package app

import (
	"context"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
)

func TestWorkflowRetentionFailureDoesNotChangeDataOutcome(t *testing.T) {
	j := workflowJob{Config: config.Config{Installation: "fixture", Retention: config.Retention{Daily: 1}}}
	repo := backup.Repository{Binary: "/missing/fixture-restic"}
	res := WorkflowResult{Status: "complete"}
	retainWorkflow(context.Background(), repo, j, &res)
	if res.Status != "complete" || res.MaintenanceError != "retention failed" {
		t.Fatal(res)
	}
	for _, status := range []string{"failed", "restored"} {
		res = WorkflowResult{Status: status}
		retainWorkflow(context.Background(), repo, j, &res)
		if res.MaintenanceError != "" || res.Status != status {
			t.Fatal("retention ran after unsuccessful backup", res)
		}
	}
	j.Config.Retention = config.Retention{}
	res = WorkflowResult{Status: "complete"}
	retainWorkflow(context.Background(), repo, j, &res)
	if res.MaintenanceError != "" {
		t.Fatal("retention not off by default", res)
	}
	j.Config.Retention = config.Retention{Daily: 1}
	j.Restore = &RestoreRequest{}
	res = WorkflowResult{Status: "complete"}
	retainWorkflow(context.Background(), repo, j, &res)
	if res.MaintenanceError != "" {
		t.Fatal("retention ran after restore", res)
	}
}
