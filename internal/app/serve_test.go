package app

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestServeValidatesScheduleAndSleepsWithoutDockerOrMutation(t *testing.T) {
	c := healthConfig(t)
	var out, diagnostics bytes.Buffer
	c.Schedule = ""
	if err := Serve(context.Background(), c, &out, &diagnostics); err == nil {
		t.Fatal("serve accepted absent schedule")
	}
	c.Schedule = "0 * * * *"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Serve(ctx, c, &out, &diagnostics); err != nil {
		t.Fatal("normal shutdown failed", err)
	}
	entries, _ := os.ReadDir(c.StateDir)
	if len(entries) != 0 {
		t.Fatal("idle scheduler mutated state", entries)
	}
}
