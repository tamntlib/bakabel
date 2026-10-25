package state

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateFilesEvenUnderRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	old := syscall.Umask(0777)
	defer syscall.Umask(old)
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"launcher.lock", "owner.json"} {
		info, e := os.Stat(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o want 600 independent of umask", name, info.Mode().Perm())
		}
	}
}

func TestRejectSymlinkStateDirectoryComponents(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if e := os.MkdirAll(filepath.Join(real, "state"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(real, filepath.Join(root, "alias")); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{filepath.Join(root, "alias"), filepath.Join(root, "alias", "state")} {
		if o, e := Acquire(p); e == nil {
			o.Close()
			t.Fatalf("followed symlink directory %s", p)
		}
	}
}

func TestRejectUntrustedDirectoryAndGuard(t *testing.T) {
	t.Run("writable directory", func(t *testing.T) {
		dir := t.TempDir()
		if e := os.Chmod(dir, 0777); e != nil {
			t.Fatal(e)
		}
		if o, e := Acquire(dir); e == nil {
			o.Close()
			t.Fatal("accepted untrusted directory")
		}
	})
	for _, kind := range []string{"symlink", "hardlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			if e := os.WriteFile(outside, []byte("unchanged"), 0600); e != nil {
				t.Fatal(e)
			}
			guard := filepath.Join(dir, "launcher.lock")
			var e error
			switch kind {
			case "symlink":
				e = os.Symlink(outside, guard)
			case "hardlink":
				e = os.Link(outside, guard)
			case "directory":
				e = os.Mkdir(guard, 0700)
			}
			if e != nil {
				t.Fatal(e)
			}
			if o, e := Acquire(dir); e == nil {
				o.Close()
				t.Fatal("accepted unsafe guard")
			}
			b, _ := os.ReadFile(outside)
			if string(b) != "unchanged" {
				t.Fatal("outside guard target changed")
			}
		})
	}
}

func TestOwnerSymlinkNeverTraversed(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "dangling"}[dangling], func(t *testing.T) {
			dir := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside.json")
			if !dangling {
				if e := os.WriteFile(outside, []byte(`{"runID":"run","daemonID":"daemon","workerName":"worker","phase":"intent","status":"active"}`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := os.Symlink(outside, filepath.Join(dir, "owner.json")); e != nil {
				t.Fatal(e)
			}
			o, e := Acquire(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer o.Close()
			if _, e = o.Load(); e == nil || errors.Is(e, ErrNoRun) {
				t.Fatalf("symlink owner considered valid/empty: %v", e)
			}
			if e = o.NewRun(initial()); !errors.Is(e, ErrOwned) {
				t.Fatalf("symlink ownership bypassed: %v", e)
			}
			r := initial()
			r.WorkerContainerID = "wc"
			if e = o.Save(r); e == nil {
				t.Fatal("Save traversed/replaced symlink")
			}
		})
	}
}

func TestDescriptorAnchoringSurvivesPathReplacement(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	moved := filepath.Join(parent, "moved")
	if e = os.Rename(dir, moved); e != nil {
		t.Fatal(e)
	}
	outside := t.TempDir()
	if e = os.Symlink(outside, dir); e != nil {
		t.Fatal(e)
	}
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(moved, "owner.json")); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(outside, "owner.json")); !os.IsNotExist(e) {
		t.Fatal("write escaped held directory")
	}
}
