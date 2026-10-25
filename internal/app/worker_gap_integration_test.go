package app

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

// Crash/response loss after durable authorization but BEFORE Engine start. No
// external worker proof is supplied to the fresh recovery process.
func TestConcreteStartAuthorizationGapRecovery(t *testing.T) {
	f := realFixture(t)
	l := workerLaunchFixture(t, f)
	dir, o := ownedDir(t)
	socket := faultProxy(t, f, func(out http.ResponseWriter, req *http.Request) bool {
		if req.Method != "POST" || !strings.HasPrefix(req.URL.Path, "/v1.55/containers/") || !strings.HasSuffix(req.URL.Path, "/start") {
			return false
		}
		r, e := o.Load()
		if e != nil || !r.WorkerStartAuthorized || r.WorkerContainerID == "" || r.ExecID == "" {
			t.Error("start before durable exact identity", r, e)
		}
		conn, _, e := out.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
		} else {
			conn.Close()
		}
		return true
	})
	c, _ := docker.NewClient(socket)
	_, e := LaunchPostgresWorker(f.ctx, o, c, f.p, l)
	if !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal("uncertain start not quarantined", e)
	}
	r, e := o.Load()
	if e != nil || !r.WorkerStartAuthorized || r.Status != state.StatusBlocked {
		t.Fatal("start gap not durable", r, e)
	}
	o.Close()
	freshConcrete(t, dir, f.socket, false)
	if code := f.api("GET", "/containers/"+r.WorkerContainerID+"/json", nil, nil); code != 404 {
		t.Fatal("never-started worker remains", code)
	}
}
