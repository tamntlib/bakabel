package files

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
)

// Self-contained and opt-in: runs exclusively inside the disposable Docker Go
// fixture. Never points at a configured repository or an application volume.
func TestRealResticFDFlattenAndSourceGone(t *testing.T) {
	binary := os.Getenv("BAKABEL_FILES_RESTIC")
	if binary == "" {
		t.Skip("opt-in disposable Restic fixture required")
	}
	ctx := context.Background()
	root := t.TempDir()
	source := WorkerPath(root, "/data")
	if e := os.MkdirAll(source, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(source)
	body := []byte("real-file-content\n")
	if e := os.WriteFile(filepath.Join(source, "payload"), body, 0640); e != nil {
		t.Fatal(e)
	}
	// Fixture permissions are explicit, not dependent on the runner's umask.
	if e := os.Chmod(filepath.Join(source, "payload"), 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(source, ".bakabel-restore"), []byte("legitimate reserved-name file"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chown(filepath.Join(source, "payload"), 1234, 2345); e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(root, "repo")
	env := append(os.Environ(), "RESTIC_REPOSITORY="+repo, "RESTIC_PASSWORD=disposable-fixture")
	cmd := exec.Command(binary, "--no-cache", "init")
	cmd.Env = env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	diagnostic := filepath.Join(root, "restic-stderr")
	wrapper := filepath.Join(root, "restic-wrapper")
	if e := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec \""+binary+"\" \"$@\" 2>>\""+diagnostic+"\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	r := backup.Repository{Binary: wrapper, Env: env}
	m, e := Capture("install", root, Volume{"daemon", "node", "volume", source, "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	result := r.Backup(ctx, m, "roundtrip", Hostname("install"), []string{"--group-by", "host,paths", "--", source})
	if result.Err != nil || result.Status != "complete" {
		t.Fatal(result)
	}
	all, e := r.Snapshots(ctx)
	if e != nil || len(all) != 1 {
		t.Fatal(all, e)
	}
	s := all[0]
	// Pin the actual baseline's limitation instead of silently claiming that a
	// proc-fd symlink can serve as Restic's root directory.
	probe, e := openDir(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	bare := exec.Command(binary, "--no-cache", "restore", s.ID+":"+m.Paths[0], "--target", "/proc/self/fd/3")
	bare.Env = env
	bare.ExtraFiles = []*os.File{probe}
	output, bareErr := bare.CombinedOutput()
	probe.Close()
	if bareErr == nil || !strings.Contains(string(output), "failed to remove stale item") {
		t.Fatal("baseline bare proc-fd behavior changed", bareErr, string(output))
	}
	t.Log("Restic 0.18.1 bare --target /proc/self/fd/3 refused: failed to remove stale item; confined real-child + renameat fallback verified below")
	dest := filepath.Join(root, "restore")
	os.Mkdir(dest, 0700)
	if e = os.RemoveAll(source); e != nil {
		t.Fatal(e)
	} // no source, scheduler or state needed now
	target, e := OpenRestore(s, dest, []string{repo})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	moved := filepath.Join(root, "pinned")
	os.Rename(dest, moved)
	os.Symlink(repo, dest)
	if e = target.Restore(ctx, r); e != nil {
		raw, _ := os.ReadFile(diagnostic)
		t.Fatal(e, string(raw))
	}
	got, e := os.ReadFile(filepath.Join(moved, "payload"))
	if e != nil || string(got) != string(body) {
		t.Fatal("flattened content", string(got), e)
	}
	st, e := os.Stat(filepath.Join(moved, "payload"))
	if e != nil {
		t.Fatal(e)
	}
	raw := st.Sys().(*syscall.Stat_t)
	if st.Mode().Perm() != 0640 || raw.Uid != 1234 || raw.Gid != 2345 {
		t.Fatal(st.Mode(), raw.Uid, raw.Gid)
	}
	entries, _ := os.ReadDir(moved)
	if len(entries) != 2 || entries[0].Name() != ".bakabel-restore" || entries[1].Name() != "payload" {
		t.Fatal("layout not flattened", entries)
	}
	reserved, e := os.ReadFile(filepath.Join(moved, ".bakabel-restore"))
	if e != nil || string(reserved) != "legitimate reserved-name file" {
		t.Fatal("reserved-name data", string(reserved), e)
	}
	t.Logf("restic exact=%s flattened=payload mode=%o uid=%d gid=%d inherited=/proc/self/fd/3 symlink-swap=confined", s.ID, st.Mode().Perm(), raw.Uid, raw.Gid)
	for _, status := range []string{"partial", "unknown"} {
		bad := s
		bad.Tags, _ = backup.EncodeTags(m, status, "bad")
		if x, e := OpenRestore(bad, t.TempDir(), nil); e == nil {
			x.Close()
			t.Fatal(strings.Join(bad.Tags, ","))
		}
	}
}
