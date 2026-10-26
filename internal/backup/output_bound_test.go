package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCappedBufferConsumesPipeWithoutBypassingLimit(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	wrote := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, strings.Repeat("x", 4096))
		_ = writer.CloseWithError(err)
		wrote <- err
	}()
	out := &cappedBuffer{limit: 64}
	n, err := io.Copy(out, reader)
	if err != nil || n != 4096 {
		t.Fatalf("pipe not fully consumed: n=%d err=%v", n, err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if !out.overflow || len(out.Bytes()) != 64 {
		t.Fatalf("pipe bypassed bound: overflow=%v bytes=%d", out.overflow, len(out.Bytes()))
	}
}

func TestSnapshotsRejectOversizedValidJSON(t *testing.T) {
	dir := t.TempDir()
	payload := filepath.Join(dir, "output")
	// Trailing whitespace keeps the JSON valid, so parsing cannot hide a
	// bypassed output cap. Exercise the actual subprocess stdout copy path.
	if err := os.WriteFile(payload, []byte("[]"+strings.Repeat(" ", 16*1024*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "restic")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat \"$BOUND_PAYLOAD\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := Repository{Binary: binary, Env: append(os.Environ(), "BOUND_PAYLOAD="+payload)}
	_, err := r.Snapshots(context.Background())
	if err == nil || err.Error() != "snapshot listing exceeds safety bound" {
		t.Fatalf("oversized valid JSON was not rejected by cap: %v", err)
	}
	var diagnostic *CommandError
	if errors.As(err, &diagnostic) {
		t.Fatalf("manufactured process failure: %v", diagnostic)
	}
}
