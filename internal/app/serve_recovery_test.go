package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tamntlib/bakabel/internal/notify"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestServeNotifiesBlockedRecoveryWithoutReleasingOwnership(t *testing.T) {
	c := healthConfig(t)
	o, err := state.Acquire(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	r := state.Record{RunID: "owned", DaemonID: "daemon", WorkerName: "worker", Phase: state.PhaseIntent, Status: state.StatusActive}
	if err = o.NewRun(r); err != nil {
		t.Fatal(err)
	}
	o.Close()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event notify.Event
		json.NewDecoder(r.Body).Decode(&event)
		if event.Status != "blocked" || event.Installation != "fixture" {
			t.Error(event)
		}
		calls++
		w.WriteHeader(204)
	}))
	defer server.Close()
	c.NotificationURLFile = filepath.Join(t.TempDir(), "endpoint")
	os.WriteFile(c.NotificationURLFile, []byte(server.URL), 0600)
	var out, diagnostics bytes.Buffer
	if err = Serve(context.Background(), c, &out, &diagnostics); err == nil {
		t.Fatal("accepted missing durable job")
	}
	if calls != 1 {
		t.Fatal("blocked recovery notification missing or retried", calls)
	}
	got, err := state.Observe(c.StateDir)
	if err != nil || got != r {
		t.Fatal("blocked recovery released ownership", got, err)
	}
}
