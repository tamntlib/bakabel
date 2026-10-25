package files

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCaptureProtectionUsesFileMetadataWithoutReading(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "protected")
	if err := os.WriteFile(p, []byte("synthetic-private-bytes"), 0000); err != nil {
		t.Fatal(err)
	}
	proof, err := CaptureProtection(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	raw := st.Sys().(*syscall.Stat_t)
	if proof.Device != uint64(raw.Dev) || proof.Inode != raw.Ino || proof.FilesystemPath == "" || validateProtection(proof) != nil {
		t.Fatal("physical file metadata missing", proof)
	}
}

func TestCaptureProtectionRejectsSymlinksAndHardLinkedFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "protected")
	if err := os.WriteFile(p, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureProtection(link); err == nil {
		t.Fatal("protected symlink was followed")
	}
	if err := os.Link(p, filepath.Join(dir, "second-name")); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureProtection(p); err == nil {
		t.Fatal("ambiguous hard-link backing accepted")
	}
}

func TestCaptureProtectionSupportsDirectoryAndSocketMetadata(t *testing.T) {
	dir := t.TempDir()
	if proof, err := CaptureProtection(dir); err != nil || validateProtection(proof) != nil {
		t.Fatal(proof, err)
	}
	path := filepath.Join(dir, "socket")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if proof, err := CaptureProtection(path); err != nil || validateProtection(proof) != nil {
		t.Fatal(proof, err)
	}
}

func TestProtectedIdentityCanCoverItsEntireBackingFilesystem(t *testing.T) {
	// A directory mounted at the root of its own tmpfs/filesystem has backing
	// path "/" even though the scheduler-visible runtime path is not host-root.
	if err := validateProtection(ProtectedIdentity{Device: 1, Inode: 2, FilesystemPath: "/"}); err != nil {
		t.Fatal("valid filesystem-root exclusion rejected", err)
	}
}
