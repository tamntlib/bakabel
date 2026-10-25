package backup

import "testing"

func fileMetadata() Metadata {
	return Metadata{Version: 1, Kind: "volume", Source: "compose/demo/files", Paths: []string{"/data"}, Mounts: []MountMetadata{{DaemonID: "daemon-fixture", NodeID: "local", Type: "volume", Name: "fixture", Source: "/volumes/fixture/_data", Destination: "/data", SnapshotPath: "/data", Device: 123, Inode: 456}}}
}

func TestFileMetadataRequiresResolvedPhysicalMount(t *testing.T) {
	m := fileMetadata()
	if _, err := EncodeTags(m, "complete", "run"); err != nil {
		t.Fatal(err)
	}
	m.Mounts[0].Inode = 0
	if _, err := EncodeTags(m, "complete", "run"); err == nil {
		t.Fatal("unresolved filesystem identity accepted")
	}
	m = fileMetadata()
	m.Mounts[0].SnapshotPath = "/other"
	if _, err := EncodeTags(m, "complete", "run"); err == nil {
		t.Fatal("snapshot path mapping mismatch accepted")
	}
	m = fileMetadata()
	m.Mounts = nil
	if _, err := EncodeTags(m, "complete", "run"); err == nil {
		t.Fatal("missing physical mount accepted")
	}
}
