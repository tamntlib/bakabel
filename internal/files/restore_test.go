package files

import (
	"context"
	"github.com/tamntlib/bakabel/internal/backup"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshot(t *testing.T, source string) backup.Snapshot {
	t.Helper()
	m, e := Capture("install", "source", Volume{"daemon", "node", "vol", source, "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	tags, e := backup.EncodeTags(m, "complete", "test")
	if e != nil {
		t.Fatal(e)
	}
	return backup.Snapshot{ID: strings.Repeat("a", 64), Tags: tags, Paths: m.Paths}
}
func TestRestoreRejectsAliasesAndNonemptyTargets(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	os.Mkdir(source, 0700)
	s := snapshot(t, source)
	child := filepath.Join(source, "child")
	os.Mkdir(child, 0700)
	other := t.TempDir()
	nonempty := filepath.Join(other, "nonempty")
	os.Mkdir(nonempty, 0700)
	os.WriteFile(filepath.Join(nonempty, "data"), []byte("x"), 0600)
	link := filepath.Join(other, "alias")
	os.Symlink(source, link)
	forbidden := filepath.Join(other, "repo")
	os.Mkdir(forbidden, 0700)
	repochild := filepath.Join(forbidden, "child")
	os.Mkdir(repochild, 0700)
	for _, p := range []string{source, child, root, link, nonempty, forbidden, repochild} {
		target, e := OpenRestore(s, p, []string{forbidden})
		if e == nil {
			target.Close()
			t.Errorf("unsafe destination accepted: %s", p)
		}
	}
}
func TestRestoreRejectsIncompleteAndWrongLayout(t *testing.T) {
	source := t.TempDir()
	s := snapshot(t, source)
	m, _, run, e := backup.DecodeTags(s.Tags)
	if e != nil {
		t.Fatal(e)
	}
	for _, status := range []string{"partial", "unknown"} {
		s.Tags, _ = backup.EncodeTags(m, status, run)
		if x, e := OpenRestore(s, t.TempDir(), nil); e == nil {
			x.Close()
			t.Errorf("accepted %s", status)
		}
	}
	s = snapshot(t, source)
	s.Paths = append(s.Paths, "/extra")
	if x, e := OpenRestore(s, t.TempDir(), nil); e == nil {
		x.Close()
		t.Fatal("accepted changed layout")
	}
}
func TestEmptySelfSourceAndUnknownMetadataFail(t *testing.T) {
	root := t.TempDir()
	s := snapshot(t, root)
	if x, e := OpenRestore(s, root, nil); e == nil {
		x.Close()
		t.Fatal("empty source accepted")
	}
	s.Tags = nil
	if x, e := OpenRestore(s, t.TempDir(), nil); e == nil {
		x.Close()
		t.Fatal("missing metadata accepted")
	}
}
func TestRestoreRejectsFilesAddedAfterPreflight(t *testing.T) {
	target, e := OpenRestore(snapshot(t, t.TempDir()), t.TempDir(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if e = os.WriteFile(filepath.Join(target.File.Name(), "late"), []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = target.Restore(context.Background(), backup.Repository{}); e == nil {
		t.Fatal("nonempty destination accepted")
	}
}
func TestOpenRestorePinsAnEmptyDirectory(t *testing.T) {
	source := t.TempDir()
	root := t.TempDir()
	dest := filepath.Join(root, "new")
	os.Mkdir(dest, 0700)
	target, e := OpenRestore(snapshot(t, source), dest, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	moved := filepath.Join(root, "moved")
	if e = os.Rename(dest, moved); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(source, dest); e != nil {
		t.Fatal(e)
	}
	info, e := target.File.Stat()
	if e != nil {
		t.Fatal(e)
	}
	wanted, _ := os.Stat(moved)
	if !os.SameFile(info, wanted) {
		t.Fatal("descriptor followed swapped pathname")
	}
	if target.Snapshot.ID != strings.Repeat("a", 64) {
		t.Fatal(target)
	}
}
