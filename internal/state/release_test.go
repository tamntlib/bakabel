package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReleaseRequiresExactOwnerAndBothTerminalProofs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Record, *TerminalProof, *Result)
	}{
		{"no proof", func(_ *Record, p *TerminalProof, _ *Result) { *p = TerminalProof{} }},
		{"worker only", func(_ *Record, p *TerminalProof, _ *Result) { p.SourceTerminal = false }},
		{"source only", func(_ *Record, p *TerminalProof, _ *Result) { p.WorkerTerminal = false }},
		{"other run", func(r *Record, _ *TerminalProof, _ *Result) { r.RunID = "other" }},
		{"stale proof", func(r *Record, _ *TerminalProof, _ *Result) { r.WorkerContainerID = "old" }},
		{"other result", func(_ *Record, _ *TerminalProof, r *Result) { r.RunID = "other" }},
		{"bad result", func(_ *Record, _ *TerminalProof, r *Result) { r.Status = "invented" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newOwner(t)
			r, p, res := initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed}
			tc.change(&r, &p, &res)
			if e := o.Release(r, p, res); e == nil {
				t.Fatal("unsafe release accepted")
			}
			if got, e := o.Load(); e != nil || got != initial() {
				t.Fatalf("ownership removed: %#v %v", got, e)
			}
			if _, e := o.LastResult(); !errors.Is(e, ErrNoResult) {
				t.Fatalf("invalid release wrote result: %v", e)
			}
		})
	}
}

func TestReleaseWritesSeparateResultBeforeDurableRemoval(t *testing.T) {
	dir := t.TempDir()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := initial()
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.Phase = PhaseQuarantine
	r.Status = StatusBlocked
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	var steps []string
	realSync, realRename := o.syncFile, o.rename
	o.syncFile = func(f *os.File) error {
		if f == o.dir {
			steps = append(steps, "directory-sync")
		} else {
			steps = append(steps, "file-sync")
		}
		return realSync(f)
	}
	o.rename = func(a int, b string, c int, d string) error {
		steps = append(steps, "rename-"+d)
		return realRename(a, b, c, d)
	}
	want := Result{RunID: "run", Status: OutcomeCanceled}
	if e = o.Release(r, TerminalProof{true, true}, want); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(steps, []string{"file-sync", "rename-last-result.json", "directory-sync", "directory-sync"}) {
		t.Fatalf("release durability order %v", steps)
	}
	if _, e = o.Load(); !errors.Is(e, ErrNoRun) {
		t.Fatalf("owner remains: %v", e)
	}
	got, e := o.LastResult()
	if e != nil || got != want {
		t.Fatalf("last result: %#v %v", got, e)
	}
	next := initial()
	next.RunID = "next"
	if e = o.NewRun(next); e != nil {
		t.Fatal(e)
	}
	if got, e = o.LastResult(); e != nil || got != want {
		t.Fatalf("NewRun changed last result: %#v %v", got, e)
	}
	o.Close()
	o, e = Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if got, e = o.LastResult(); e != nil || got != want {
		t.Fatalf("result not durable: %#v %v", got, e)
	}
}

func TestResultFailureKeepsOwnership(t *testing.T) {
	o := newOwner(t)
	injected := errors.New("result fsync failed")
	o.syncFile = func(*os.File) error { return injected }
	if e := o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed}); !errors.Is(e, injected) {
		t.Fatalf("failure hidden: %v", e)
	}
	if _, e := o.Load(); e != nil {
		t.Fatalf("owner lost after result failure: %v", e)
	}
}

func TestLastResultBoundedAndNoSymlinkTraversal(t *testing.T) {
	for name, data := range map[string]string{"oversize": `{"runID":"r","status":"failed"}` + strings.Repeat(" ", 512), "unknown": `{"runID":"r","status":"future"}`, "duplicate": `{"runID":"a","runID":"b","status":"failed"}`} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := os.WriteFile(filepath.Join(dir, "last-result.json"), []byte(data), 0600); e != nil {
				t.Fatal(e)
			}
			o, e := Acquire(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if _, e = o.LastResult(); e == nil || errors.Is(e, ErrNoResult) {
				t.Fatalf("bad result accepted/absent: %v", e)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		outside := filepath.Join(t.TempDir(), "result")
		if e := os.WriteFile(outside, []byte(`{"runID":"other","status":"failed"}`), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink(outside, filepath.Join(dir, "last-result.json")); e != nil {
			t.Fatal(e)
		}
		o, e := Acquire(dir)
		if e != nil {
			t.Fatal(e)
		}
		defer o.Close()
		if e = o.NewRun(initial()); e != nil {
			t.Fatal(e)
		}
		if _, e = o.LastResult(); e == nil || errors.Is(e, ErrNoResult) {
			t.Fatalf("followed result symlink: %v", e)
		}
		if e = o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed}); e == nil {
			t.Fatal("release replaced unsafe result path")
		}
		if _, e = o.Load(); e != nil {
			t.Fatal("unsafe result caused owner removal")
		}
	})
}
