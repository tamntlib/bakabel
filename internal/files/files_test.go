package files

import (
	"github.com/tamntlib/bakabel/internal/backup"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOnlyKnownLocalFilesystemIdentitiesAccepted(t *testing.T) {
	for _, magic := range []int64{0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630} {
		if !localFilesystem(magic) {
			t.Errorf("local fs rejected: %x", magic)
		}
	}
	for _, magic := range []int64{0x6969, 0xff534d42, 0x65735546, 0x01021997, 0xdeadbeef} {
		if localFilesystem(magic) {
			t.Errorf("opaque/network fs accepted: %x", magic)
		}
	}
}
func TestMetadataRefusesMalformedFilesystemPath(t *testing.T) {
	s := snapshot(t, t.TempDir())
	m, _, _, e := backup.DecodeTags(s.Tags)
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"../unsafe", "/data/../unsafe", "/data\nunsafe"} {
		m.Mounts[0].FilesystemPath = p
		if _, e = backup.EncodeTags(m, "complete", "run"); e == nil {
			t.Errorf("invalid backing path accepted: %q", p)
		}
	}
}
func TestCaptureOneMountStableMetadata(t *testing.T) {
	root := t.TempDir()
	v := Volume{DaemonID: "daemon", NodeID: "node", Name: "uploads", Mountpoint: "/var/lib/docker/volumes/uploads/_data", Destination: "/data"}
	a, err := Capture("installation", "compose/project/service/data", v, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Capture("installation", "compose/project/service/data", v, root)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatal(a, b, err)
	}
	if len(a.Paths) != 1 || len(a.Mounts) != 1 || a.Mounts[0].Inode == 0 || a.Mounts[0].Device == 0 || a.Paths[0] != a.Mounts[0].SnapshotPath {
		t.Fatal(a)
	}
	if a.Paths[0] != WorkerPath(a.Source, "/data") || Hostname("installation") == Hostname("other") {
		t.Fatal(a)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(a.Paths[0]) == false {
		t.Fatal(a.Paths)
	}
}
