package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/notify"
	"gopkg.in/yaml.v3"
)

func TestPublicRunFailureNotifiesOnce(t *testing.T) {
	c := healthConfig(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	c.NotificationURLFile = filepath.Join(t.TempDir(), "endpoint")
	os.WriteFile(c.NotificationURLFile, []byte(server.URL), 0600)
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, b, 0600)
	var out, diagnostics bytes.Buffer
	if code := Main(context.Background(), []string{"--config", p, "run"}, &out, &diagnostics); code == 0 {
		t.Fatal("run succeeded without Docker")
	}
	if calls.Load() != 1 {
		t.Fatal("CLI omitted or retried failure notification", calls.Load())
	}
}

func TestRealScheduleReportsActualDueFailureOnce(t *testing.T) {
	if os.Getenv("BAKABEL_REAL_SCHEDULE") != "1" {
		t.Skip("set BAKABEL_REAL_SCHEDULE=1 for a real minute timer")
	}
	c := healthConfig(t)
	c.Schedule = "* * * * *"
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	events := make(chan notify.Event, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event notify.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		events <- event
		w.WriteHeader(204)
		cancel()
	}))
	defer server.Close()
	c.NotificationURLFile = filepath.Join(t.TempDir(), "endpoint")
	os.WriteFile(c.NotificationURLFile, []byte(server.URL), 0600)
	var out, diagnostics bytes.Buffer
	if err := Serve(ctx, c, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Installation != "fixture" || event.Status != "failed" {
			t.Fatal(event)
		}
	default:
		t.Fatal("scheduled failure was not notified", out.String(), diagnostics.String())
	}
	if len(events) != 0 {
		t.Fatal("scheduler replayed the missed occurrence")
	}
	var event serveEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &event); err != nil || !event.Failed || event.Operation != "backup" {
		t.Fatal("actual scheduled result not observed", out.String(), err)
	}
	entries, _ := os.ReadDir(c.StateDir)
	if len(entries) != 0 {
		t.Fatal("failed discovery mutated state", entries)
	}
}
