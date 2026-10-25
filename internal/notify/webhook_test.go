package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func urlFile(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "webhook")
	if err := os.WriteFile(p, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFailureWebhookUsesFileAndFixedPayload(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong request")
		}
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		if event.Installation != "fixture" || event.Status != "failed" || event.RunID != "run" {
			t.Error(event)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	if err := Failure(context.Background(), urlFile(t, server.URL+"?token=fixture-secret\n"), Event{Installation: "fixture", RunID: "run", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("notification was retried or omitted", calls)
	}
	if err := Failure(context.Background(), "", Event{}); err != nil {
		t.Fatal("default notification is not off", err)
	}
}

func TestWebhookFailureDoesNotLeakURLOrFollowRedirects(t *testing.T) {
	redirected := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected++ }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/private", http.StatusFound)
	}))
	defer server.Close()
	err := Failure(context.Background(), urlFile(t, server.URL+"?token=fixture-secret"), Event{Installation: "fixture", Status: "failed"})
	if err == nil || redirected != 0 || strings.Contains(err.Error(), "fixture-secret") || strings.Contains(err.Error(), server.URL) {
		t.Fatal("unsafe notification error", err, redirected)
	}
	if err = Failure(context.Background(), "/missing/private-webhook", Event{Installation: "fixture", Status: "failed"}); err == nil || strings.Contains(err.Error(), "private-webhook") {
		t.Fatal("private filename leaked", err)
	}
}
