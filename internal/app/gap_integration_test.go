package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

// API fault injection uses the real Engine for every nonfaulting request.
func faultProxy(t *testing.T, f *fixture, fault func(http.ResponseWriter, *http.Request) bool) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", f.socket)
	}}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fault(w, r) {
			return
		}
		r.RequestURI = ""
		r.URL.Scheme = "http"
		r.URL.Host = "docker"
		response, e := transport.RoundTrip(r)
		if e != nil {
			http.Error(w, "fixture unavailable", 502)
			return
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusSwitchingProtocols {
			conn, buf, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			fmt.Fprintf(buf, "HTTP/1.1 %s\r\n", response.Status)
			response.Header.Write(buf)
			fmt.Fprint(buf, "\r\n")
			buf.Flush()
			io.Copy(conn, response.Body)
			return
		}
		for k, vs := range response.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close(); transport.CloseIdleConnections() })
	return socket
}
func TestRealCreateResponseGapDurablyQuarantines(t *testing.T) {
	f := realFixture(t)
	dir, o := ownedDir(t)
	run := token(t)
	worker := "helper-" + run
	var mu sync.Mutex
	var lostID string
	socket := faultProxy(t, f, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/containers/"+f.id+"/exec") {
			return false
		}
		durable, e := o.Load()
		if e != nil || durable.Phase != state.PhaseCreatingExec || durable.ExecID != "" || durable.WorkerName != worker {
			t.Error("create sent before durable intended ownership", durable, e)
		}
		// Forward the real create, but lose its successful response before the parent
		// can persist the ID. The external exec really exists; it is never started.
		r.RequestURI = ""
		r.URL.Scheme = "http"
		r.URL.Host = "docker"
		response, e := f.http.Transport.RoundTrip(r)
		if e != nil {
			t.Error(e)
			return true
		}
		defer response.Body.Close()
		var created struct {
			ID string `json:"Id"`
		}
		if json.NewDecoder(response.Body).Decode(&created) != nil {
			t.Error("create response")
		}
		mu.Lock()
		lostID = created.ID
		mu.Unlock()
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
		} else {
			conn.Close()
		}
		return true
	})
	client, e := docker.NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	_, e = Prepare(f.ctx, o, client, f.p, run, worker)
	if !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal("create uncertainty accepted", e)
	}
	mu.Lock()
	id := lostID
	mu.Unlock()
	if id == "" {
		t.Fatal("no real exec created")
	}
	x, e := f.c.PollExec(f.ctx, id)
	if e != nil || x.Running {
		t.Fatal("lost exec prematurely started", x, e)
	}
	got, e := o.Load()
	if e != nil || got.ExecID != "" || got.Status != state.StatusBlocked || got.Phase != state.PhaseQuarantine {
		t.Fatal("missing create-gap quarantine", got, e)
	}
	o.Close()
	// No worker was ever launched by this fixture. The fresh controller still may
	// not invent the lost exec ID or auto-release based on elapsed time/absence.
	freshRecovery(t, dir, f.socket, worker, 2147483646, true)
	t.Logf("real create response lost exec=%s durable execID empty; fresh controller retained quarantine", id)
}
