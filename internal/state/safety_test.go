package state

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOldTimestampNeverUnlocksOwnership(t *testing.T) {
	dir := t.TempDir()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	o.Close()
	ancient := time.Unix(1, 0)
	if e = os.Chtimes(filepath.Join(dir, "owner.json"), ancient, ancient); e != nil {
		t.Fatal(e)
	}
	o, e = Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	next := initial()
	next.RunID = "next"
	if e = o.NewRun(next); !errors.Is(e, ErrOwned) {
		t.Fatalf("stale timestamp admitted another run: %v", e)
	}
}

func TestClosedOwnerCannotReadOrMutate(t *testing.T) {
	o := newOwner(t)
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := o.Load(); !errors.Is(e, ErrClosed) {
		t.Fatalf("Load: %v", e)
	}
	if _, e := o.LastResult(); !errors.Is(e, ErrClosed) {
		t.Fatalf("LastResult: %v", e)
	}
	for _, e := range []error{o.NewRun(initial()), o.Save(initial()), o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed})} {
		if !errors.Is(e, ErrClosed) {
			t.Fatalf("closed mutation: %v", e)
		}
	}
}

func TestConcurrentSavesNeverOverwriteEstablishedIdentity(t *testing.T) {
	o := newOwner(t)
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for _, id := range []string{"a", "b", "c", "d"} {
		wg.Go(func() {
			r := initial()
			r.WorkerContainerID = id
			if e := o.Save(r); e == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("identity winners %d", successes)
	}
}

func TestNonregularStateFilesRefusedWithoutBlocking(t *testing.T) {
	for _, name := range []string{"owner.json", "last-result.json", "launcher.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if e := syscall.Mkfifo(filepath.Join(dir, name), 0600); e != nil {
				t.Fatal(e)
			}
			o, e := Acquire(dir)
			if name == "launcher.lock" {
				if e == nil {
					o.Close()
					t.Fatal("FIFO guard accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if name == "owner.json" {
				if _, e = o.Load(); e == nil {
					t.Fatal("FIFO owner accepted")
				}
				if e = o.NewRun(initial()); !errors.Is(e, ErrOwned) {
					t.Fatalf("FIFO owner bypassed: %v", e)
				}
			} else {
				if _, e = o.LastResult(); e == nil {
					t.Fatal("FIFO result accepted")
				}
			}
		})
	}
}

func TestCorruptStateCannotBeReleasedEvenWithProof(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "owner.json"), []byte(`{"pid":1,"phase":"stale"}`), 0600); e != nil {
		t.Fatal(e)
	}
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if e = o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed}); e == nil {
		t.Fatal("corrupt record was force-released")
	}
	if _, e = os.Stat(filepath.Join(dir, "owner.json")); e != nil {
		t.Fatal("corrupt evidence removed")
	}
}

func TestReleaseDirectorySyncFailureStatesAreExplicit(t *testing.T) {
	for _, which := range []int{1, 2} {
		t.Run(string(rune('0'+which)), func(t *testing.T) {
			o := newOwner(t)
			real := o.syncFile
			count := 0
			injected := errors.New("directory sync failed")
			o.syncFile = func(f *os.File) error {
				if f == o.dir {
					count++
					if count == which {
						return injected
					}
				}
				return real(f)
			}
			if e := o.Release(initial(), TerminalProof{true, true}, Result{RunID: "run", Status: OutcomeFailed}); !errors.Is(e, injected) {
				t.Fatalf("directory failure hidden: %v", e)
			}
			_, e := o.Load()
			if which == 1 && e != nil {
				t.Fatalf("owner removed before result durability: %v", e)
			}
			if which == 2 && !errors.Is(e, ErrNoRun) {
				t.Fatalf("post-unlink owner should be absent, durability uncertain: %v", e)
			}
			if e = o.NewRun(initial()); !errors.Is(e, ErrUncertain) {
				t.Fatalf("mutation after failed release: %v", e)
			}
		})
	}
}

func TestPendingEntryNeverFollowedOrCleanedOnRecovery(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "sentinel")
	if e := os.WriteFile(outside, []byte("unchanged"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, ".pending")); e != nil {
		t.Fatal(e)
	}
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if e = o.NewRun(initial()); e == nil {
		t.Fatal("pending symlink reused")
	}
	b, e := os.ReadFile(outside)
	if e != nil || string(b) != "unchanged" {
		t.Fatal("pending target changed")
	}
	if _, e = os.Lstat(filepath.Join(dir, ".pending")); e != nil {
		t.Fatal("foreign pending entry cleaned")
	}
}
