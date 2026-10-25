package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictBoundedOwnerRecord(t *testing.T) {
	valid := `{"runID":"run","daemonID":"daemon","workerName":"worker","phase":"intent","status":"active"}`
	cases := map[string]string{
		"oversize":        valid + strings.Repeat(" ", 4096),
		"duplicate field": strings.Replace(valid, `"runID":"run"`, `"runID":"old","runID":"run"`, 1),
		"unknown field":   strings.TrimSuffix(valid, "}") + `,"password":"secret"}`,
		"wrong case":      strings.Replace(valid, "runID", "RunID", 1),
		"null optional":   strings.TrimSuffix(valid, "}") + `,"execID":null}`,
		"trailing object": valid + valid,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
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
				t.Fatal("ambiguous/oversized record accepted")
			}
			if e = o.Save(initial()); e == nil {
				t.Fatal("ambiguous/oversized record overwritten")
			}
		})
	}
}
