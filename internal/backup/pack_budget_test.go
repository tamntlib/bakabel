package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// This subprocess records actual argv, not a repository/runtime acceptance.
func packBudgetRepository(t *testing.T) (Repository, string, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "restic")
	script := `#!/bin/sh
case "$2" in
snapshots) if [ -f "$PACK_TEST_DIR/forgotten" ]; then printf '[]'; else cat "$PACK_TEST_DIR/before"; fi;;
backup|prune) printf '%s\000' "$@" > "$PACK_TEST_DIR/argv"
              [ "$2" = backup ] && exit 1;;
forget) touch "$PACK_TEST_DIR/forgotten";;
*) exit 99;;
esac
exit 0
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "before"), []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	return Repository{Binary: binary, Env: append(os.Environ(), "PACK_TEST_DIR="+dir)}, filepath.Join(dir, "argv"), dir
}

func TestBackupUsesSmallPacksWithoutChangingProducerArgv(t *testing.T) {
	r, capture, _ := packBudgetRepository(t)
	source := []string{"--stdin-filename", "database.dump", "--stdin-from-command", "--", "/fixed-helper", "literal argument", "--literal"}
	res := r.Backup(context.Background(), fileMetadata(), "pack-budget", "fixture", source)
	if res.Err == nil || res.Status != "unknown" || res.FailureStage != "backup" {
		t.Fatalf("failure semantics changed: %+v", res)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if bytes.Count(raw, []byte("--pack-size=4\x00")) != 1 {
		t.Fatal("backup omitted the measured small-pack policy")
	}
	if !reflect.DeepEqual(argv[len(argv)-len(source):], source) {
		t.Fatal("pack option changed producer arguments")
	}
}

func TestRetentionPruneUsesSameSmallPackPolicy(t *testing.T) {
	r, capture, dir := packBudgetRepository(t)
	m := fileMetadata()
	tags, err := EncodeTags(m, "complete", "pack-budget")
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal([]Snapshot{{ID: strings.Repeat("a", 64), Tags: tags, Paths: m.Paths, Hostname: "fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "before"), before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Retain(context.Background(), Retention{Daily: 1}, "fixture", "compose", true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if !reflect.DeepEqual(argv, []string{"--no-cache", "prune", "--pack-size=4"}) {
		t.Fatal("prune omitted the shared small-pack policy")
	}
}
