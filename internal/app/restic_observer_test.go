package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
)

// TestResticObserver executes the real pinned Restic on every call. Immediately
// before the adapter's tag command it reads actual repository state, so the test
// can assert the committed unknown ID as well as the changed complete ID. This
// intercepts only the command boundary, not source export or Restic responses.
func TestResticObserver(t *testing.T) {
	if os.Getenv("BAKABEL_B1_RESTIC_OBSERVER") != "1" {
		return
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	for _, a := range args {
		if a == "tag" {
			c := exec.Command(os.Getenv("RESTIC_TEST_BINARY"), "--no-cache", "snapshots", "--json")
			c.Env = os.Environ()
			b, e := c.Output()
			if e != nil || os.WriteFile(os.Getenv("BAKABEL_B1_UNKNOWN"), b, 0600) != nil {
				os.Exit(2)
			}
			break
		}
	}
	c := exec.Command(os.Getenv("RESTIC_TEST_BINARY"), args...)
	c.Env = os.Environ()
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if e := c.Run(); e != nil {
		if exit, ok := e.(*exec.ExitError); ok {
			os.Exit(exit.ExitCode())
		}
		os.Exit(2)
	}
	os.Exit(0)
}
func observeUnknown(t *testing.T, r backup.Repository) (backup.Repository, string) {
	t.Helper()
	dir := t.TempDir()
	bin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	script := filepath.Join(dir, "restic-observer")
	file := filepath.Join(dir, "unknown.json")
	if e = os.WriteFile(script, []byte("#!/bin/sh\nexec '"+bin+"' -test.run=^TestResticObserver$ -- \"$@\"\n"), 0700); e != nil {
		t.Fatal(e)
	}
	r.Binary = script
	r.Env = append(r.Env, "BAKABEL_B1_RESTIC_OBSERVER=1", "BAKABEL_B1_UNKNOWN="+file)
	return r, file
}
func assertUnknownTransition(t *testing.T, file, finalID string) {
	t.Helper()
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	var snapshots []backup.Snapshot
	if e = json.Unmarshal(b, &snapshots); e != nil || len(snapshots) != 1 {
		t.Fatal("unknown readback", e)
	}
	_, status, _, e := backup.DecodeTags(snapshots[0].Tags)
	if e != nil || status != "unknown" || snapshots[0].ID == finalID {
		t.Fatal("unknown -> complete exact ID mutation", snapshots, e)
	}
	t.Logf("actual unknownID=%s -> complete finalID=%s (Restic tag changed ID)", snapshots[0].ID, finalID)
}
