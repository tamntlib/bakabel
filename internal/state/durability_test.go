package state

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAtomicWriteSyncOrder(t *testing.T) {
	o, e := Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	var steps []string
	syncReal, renameReal := o.syncFile, o.rename
	o.syncFile = func(f *os.File) error {
		if f == o.dir {
			steps = append(steps, "directory-sync")
		} else {
			steps = append(steps, "file-sync")
		}
		return syncReal(f)
	}
	o.rename = func(a int, b string, c int, d string) error {
		steps = append(steps, "rename")
		return renameReal(a, b, c, d)
	}
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(steps, []string{"file-sync", "rename", "directory-sync"}) {
		t.Fatalf("durability order: %v", steps)
	}
	steps = nil
	r := initial()
	r.WorkerContainerID = "wc"
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(steps, []string{"file-sync", "rename", "directory-sync"}) {
		t.Fatalf("Save durability order: %v", steps)
	}
}

func TestSaveReplacesRatherThanTruncates(t *testing.T) {
	dir := t.TempDir()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	old, e := os.Open(filepath.Join(dir, "owner.json"))
	if e != nil {
		t.Fatal(e)
	}
	defer old.Close()
	before, _ := io.ReadAll(old)
	r := initial()
	r.WorkerContainerID = "wc"
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	old.Seek(0, 0)
	after, _ := io.ReadAll(old)
	if string(after) != string(before) {
		t.Fatal("Save mutated already-open inode (not atomic replacement)")
	}
	got, e := o.Load()
	if e != nil || got != r {
		t.Fatalf("new inode missing: %#v %v", got, e)
	}
	info, e := os.Stat(filepath.Join(dir, "owner.json"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private state mode %o", info.Mode().Perm())
	}
}

func TestAtomicFailuresDoNotAllowFurtherMutations(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			o, e := Acquire(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if e = o.NewRun(initial()); e != nil {
				t.Fatal(e)
			}
			injected := errors.New("injected disk error")
			realSync := o.syncFile
			o.syncFile = func(f *os.File) error {
				if stage == "file-sync" && f != o.dir || stage == "directory-sync" && f == o.dir {
					return injected
				}
				return realSync(f)
			}
			if stage == "rename" {
				o.rename = func(int, string, int, string) error { return injected }
			}
			r := initial()
			r.WorkerContainerID = "wc"
			if e = o.Save(r); !errors.Is(e, injected) {
				t.Fatalf("failure not propagated: %v", e)
			}
			got, e := o.Load()
			if e != nil {
				t.Fatal(e)
			}
			if stage == "directory-sync" {
				if got != r {
					t.Fatal("post-rename content should be visible despite failed directory sync")
				}
			} else if got != initial() {
				t.Fatal("failed pre-rename write changed owner")
			}
			if e = o.Save(r); e == nil {
				t.Fatal("disk failure did not poison mutation handle")
			}
			entries, e := os.ReadDir(dir)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if entry.Name() != "owner.json" && entry.Name() != "launcher.lock" {
					t.Fatalf("temporary leak %s", entry.Name())
				}
			}
		})
	}
}
