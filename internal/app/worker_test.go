package app

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerRecordsBoundedPrivateNoReplace(t *testing.T) {
	dir := t.TempDir()
	value := WorkerResult{RunID: strings.Repeat("a", 32), Status: "partial", SnapshotID: strings.Repeat("b", 64), Error: "backup failed"}
	if e := publishJSON(dir, "result.json", value, 1024); e != nil {
		t.Fatal(e)
	}
	if e := publishJSON(dir, "result.json", WorkerResult{}, 1024); e == nil {
		t.Fatal("overwrote existing run receipt")
	}
	st, e := os.Stat(filepath.Join(dir, "result.json"))
	if e != nil || st.Mode().Perm() != 0600 || st.Size() > 1024 {
		t.Fatal("unbounded/nonprivate", st, e)
	}
	var got WorkerResult
	if e = readJSON(filepath.Join(dir, "result.json"), &got, 1024); e != nil || got != value {
		t.Fatal("readback", got, e)
	}
	if e = publishJSON(dir, "too-big", strings.Repeat("x", 2048), 1024); e == nil {
		t.Fatal("oversized record published")
	}
	if e = os.Symlink(filepath.Join(dir, "result.json"), filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if readJSON(filepath.Join(dir, "link"), &got, 1024) == nil {
		t.Fatal("followed symlink")
	}
	for _, bad := range []string{`{"runID":"a","status":"complete","snapshotID":"` + strings.Repeat("z", 64) + `"}`, `{"runID":"a","status":"complete","snapshotID":"` + strings.Repeat("b", 64) + `","error":"raw secret error"}`, `{"runID":"a","status":"unknown","command":"sh"}`} {
		p := filepath.Join(dir, "bad")
		if e = os.WriteFile(p, []byte(bad), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = readWorkerResult(p); e == nil {
			t.Fatal("invalid worker receipt accepted")
		}
	}
	if code := Main(context.Background(), []string{"_worker", "--command", "sh"}, io.Discard, io.Discard); code == 0 {
		t.Fatal("worker arbitrary command accepted")
	}
}
