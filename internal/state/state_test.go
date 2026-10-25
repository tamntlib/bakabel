package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDurableOwnershipSurvivesGuardClose(t *testing.T) {
	dir := t.TempDir()
	o, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Load(); !errors.Is(err, ErrNoRun) {
		t.Fatalf("empty: %v", err)
	}
	want := Record{RunID: "run-1", DaemonID: "daemon-1", WorkerName: "worker-1", Phase: PhaseIntent, Status: StatusActive}
	if err := o.NewRun(want); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	got, err := next.Load()
	if err != nil || got != want {
		t.Fatalf("durable record: %#v, %v", got, err)
	}
	want.RunID = "run-2"
	if err := next.NewRun(want); !errors.Is(err, ErrOwned) {
		t.Fatalf("existing ownership: %v", err)
	}
}

func TestExecLifecycle(t *testing.T) {
	o, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	r := Record{RunID: "run", DaemonID: "daemon", WorkerName: "worker", Phase: PhaseIntent, Status: StatusActive}
	if err := o.NewRun(r); err != nil {
		t.Fatal(err)
	}
	r.WorkerContainerID = "worker-cid"
	r.SourceContainerID = "source-cid"
	r.SourceStartedAt = "2026-10-25T04:02:06.203272873Z"
	r.Phase = PhaseCreatingExec
	if err := o.Save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := o.Load(); err != nil || got != r {
		t.Fatalf("must persist creating before CreateExec: %#v %v", got, err)
	}
	r.ExecID = "exact-exec"
	r.Phase = PhaseExecCreated
	if err := o.Save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := o.Load(); err != nil || got != r {
		t.Fatalf("must persist exec ID before start: %#v %v", got, err)
	}
	r.Phase = PhaseExecStarted
	if err := o.Save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := o.Load(); err != nil || got != r {
		t.Fatalf("started: %#v %v", got, err)
	}
}

func initial() Record {
	return Record{RunID: "run", DaemonID: "daemon", WorkerName: "worker", Phase: PhaseIntent, Status: StatusActive}
}
func newOwner(t *testing.T) *Owner {
	t.Helper()
	o, e := Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { o.Close() })
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	return o
}

func TestRejectInvalidNewRun(t *testing.T) {
	cases := map[string]func(*Record){
		"empty run":                  func(r *Record) { r.RunID = "" },
		"empty daemon":               func(r *Record) { r.DaemonID = "" },
		"empty worker":               func(r *Record) { r.WorkerName = "" },
		"oversize":                   func(r *Record) { r.RunID = strings.Repeat("x", 129) },
		"unsafe token":               func(r *Record) { r.WorkerName = "secret\npassword" },
		"unknown phase":              func(r *Record) { r.Phase = "future" },
		"unknown status":             func(r *Record) { r.Status = "complete" },
		"skipped intent":             func(r *Record) { r.Phase = PhaseExecStarted; r.ExecID = "e" },
		"premature exec":             func(r *Record) { r.ExecID = "e" },
		"source without incarnation": func(r *Record) { r.SourceContainerID = "c" },
		"bad incarnation":            func(r *Record) { r.SourceContainerID = "c"; r.SourceStartedAt = "yesterday" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o, e := Acquire(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			r := initial()
			change(&r)
			if e := o.NewRun(r); e == nil {
				t.Fatal("invalid NewRun accepted")
			}
			if _, e := o.Load(); !errors.Is(e, ErrNoRun) {
				t.Fatalf("invalid input created ownership: %v", e)
			}
		})
	}
}

func TestSaveOnlySameRunForwardIdentity(t *testing.T) {
	cases := map[string]func(*Record){
		"run":         func(r *Record) { r.RunID = "other" },
		"daemon":      func(r *Record) { r.DaemonID = "other" },
		"worker name": func(r *Record) { r.WorkerName = "other" },
		"source":      func(r *Record) { r.SourceContainerID = "other" },
		"incarnation": func(r *Record) { r.SourceStartedAt = "2026-10-26T00:00:00Z" },
		"worker ID":   func(r *Record) { r.WorkerContainerID = "other" },
		"exec ID":     func(r *Record) { r.ExecID = "other" },
		"regression":  func(r *Record) { r.Phase = PhaseCreatingExec; r.ExecID = "" },
		"unknown":     func(r *Record) { r.Phase = "alien" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := newOwner(t)
			r := initial()
			r.WorkerContainerID = "wc"
			r.SourceContainerID = "sc"
			r.SourceStartedAt = "2026-10-25T00:00:00Z"
			r.Phase = PhaseCreatingExec
			if e := o.Save(r); e != nil {
				t.Fatal(e)
			}
			r.ExecID = "exec"
			r.Phase = PhaseExecCreated
			if e := o.Save(r); e != nil {
				t.Fatal(e)
			}
			bad := r
			change(&bad)
			if e := o.Save(bad); e == nil {
				t.Fatal("identity/phase rewrite accepted")
			}
			if got, e := o.Load(); e != nil || got != r {
				t.Fatalf("rejected update changed state: %#v %v", got, e)
			}
		})
	}
	t.Run("skipped creating", func(t *testing.T) {
		o := newOwner(t)
		r := initial()
		r.SourceContainerID = "sc"
		r.SourceStartedAt = "2026-10-25T00:00:00Z"
		r.ExecID = "e"
		r.Phase = PhaseExecCreated
		if e := o.Save(r); e == nil {
			t.Fatal("skipped creating")
		}
	})
	t.Run("no owner", func(t *testing.T) {
		o, e := Acquire(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		defer o.Close()
		if e := o.Save(initial()); e == nil {
			t.Fatal("Save created absent ownership")
		}
	})
}

func TestQuarantineIsStickyAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := initial()
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.Phase = PhaseQuarantine
	r.Status = StatusBlocked
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	o.Close()
	o, e = Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if e = o.NewRun(initial()); !errors.Is(e, ErrOwned) {
		t.Fatalf("quarantine bypassed: %v", e)
	}
	if e = o.Save(initial()); e == nil {
		t.Fatal("quarantine cleared without proof")
	}
}

func TestCorruptOrUnknownStateBlocks(t *testing.T) {
	for _, data := range []string{`{`, `{}`, `null`, `{"runID":"old","daemonID":"d","workerName":"w","phase":"unknown","status":"active"}`, `{"runID":"old","daemonID":"d","workerName":"w","phase":"intent","status":"done"}`} {
		t.Run(data, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.WriteFile(filepath.Join(dir, "owner.json"), []byte(data), 0600); e != nil {
				t.Fatal(e)
			}
			o, e := Acquire(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if _, e = o.Load(); e == nil {
				t.Fatal("bad owner accepted")
			}
			if e = o.NewRun(initial()); !errors.Is(e, ErrOwned) {
				t.Fatalf("bad owner overwritten: %v", e)
			}
			if e = o.Save(initial()); e == nil {
				t.Fatal("bad owner repaired implicitly")
			}
			got, _ := os.ReadFile(filepath.Join(dir, "owner.json"))
			if string(got) != data {
				t.Fatal("corrupt evidence altered")
			}
		})
	}
}

func TestGuardContention(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if other, err := Acquire(dir); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("second launcher: %v, want ErrBusy", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
}
