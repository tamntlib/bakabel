package backup

import (
	"strings"
	"testing"
)

func TestOnlyCompleteSelfContainedSnapshotIsRestorable(t *testing.T) {
	meta := fileMetadata()
	for _, status := range []string{"unknown", "partial", "complete"} {
		tags, err := EncodeTags(meta, status, "run")
		if err != nil {
			t.Fatal(err)
		}
		snapshot := Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: meta.Paths, Hostname: "fixture"}
		got, err := snapshot.Restorable()
		if status == "complete" {
			if err != nil || got.Source != meta.Source {
				t.Fatalf("complete snapshot rejected: %v", err)
			}
			snapshot.Paths = []string{"/elsewhere"}
			if _, err = snapshot.Restorable(); err == nil {
				t.Fatal("path mismatch accepted for restore")
			}
		} else if err == nil {
			t.Fatalf("%s snapshot allowed for restore", status)
		}
	}
	if _, err := (Snapshot{ID: "latest"}).Restorable(); err == nil {
		t.Fatal("implicit latest accepted")
	}
}
