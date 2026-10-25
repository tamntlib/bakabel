package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailureReportingDoesNotMaskOutcomeOrLeakEndpoint(t *testing.T) {
	c := healthConfig(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	c.NotificationURLFile = filepath.Join(t.TempDir(), "endpoint")
	os.WriteFile(c.NotificationURLFile, []byte(server.URL+"?token=private-fixture"), 0600)
	var diagnostics bytes.Buffer
	result := WorkflowResult{RunID: "run", Status: "complete", MaintenanceError: "retention failed"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reportFailure(ctx, c, result, errors.New("private-original-error"), &diagnostics)
	if calls != 1 || result.Status != "complete" {
		t.Fatal("notification skipped, retried or changed backup outcome", calls, result)
	}
	if strings.Contains(diagnostics.String(), "private") || strings.Contains(diagnostics.String(), server.URL) || !strings.Contains(diagnostics.String(), "notification") {
		t.Fatal("unsafe notification diagnostic", diagnostics.String())
	}
	reportFailure(context.Background(), c, result, nil, &diagnostics)
	if calls != 1 {
		t.Fatal("notified for successful workflow")
	}
}
