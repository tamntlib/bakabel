// Package files implements the Linux single-local-volume file backup contract.
package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tamntlib/bakabel/internal/backup"
)

// Volume is supplied only after Docker has inspected the exact local-driver,
// option-free volume mount. Mountpoint is the daemon-native source, not a label.
type Volume struct{ DaemonID, NodeID, Name, Mountpoint, Destination string }

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func WorkerPath(source, destination string) string {
	return "/bakabel/files/" + digest(source+"\x00"+destination)
}
func Hostname(installation string) string { return "bakabel-" + digest(installation) }

// Capture stats the actual mounted source root in the worker, never the name of
// the volume or the application's writable layer. The caller must map precisely
// this volume read-only at WorkerPath before invoking Restic directly.
func Capture(installation, source string, v Volume, mountedRoot string) (backup.Metadata, error) {
	if installation == "" || source == "" || v.DaemonID == "" || v.NodeID == "" || v.Name == "" || !cleanPath(v.Mountpoint) || !cleanPath(v.Destination) {
		return backup.Metadata{}, errors.New("incomplete inspected file volume")
	}
	f, e := openDir(mountedRoot)
	if e != nil {
		return backup.Metadata{}, e
	}
	defer f.Close()
	if e = requireLocal(f); e != nil {
		return backup.Metadata{}, e
	}
	var st syscall.Stat_t
	if e = syscall.Fstat(int(f.Fd()), &st); e != nil {
		return backup.Metadata{}, e
	}
	backing, e := filesystemPath(f)
	if e != nil {
		return backup.Metadata{}, e
	}
	p := WorkerPath(source, v.Destination)
	m := backup.Metadata{Version: 1, Kind: "volume", Source: source, Paths: []string{p}, Mounts: []backup.MountMetadata{{DaemonID: v.DaemonID, NodeID: v.NodeID, Type: "volume", Name: v.Name, Source: v.Mountpoint, Destination: v.Destination, SnapshotPath: p, Device: uint64(st.Dev), Inode: st.Ino, FilesystemPath: backing}}}
	_, e = backup.EncodeTags(m, "unknown", "capture")
	return m, e
}
func localFilesystem(magic int64) bool {
	// ext2/3/4, XFS, Btrfs, tmpfs and overlayfs are the deliberately narrow
	// tested Linux baseline. Unknown, FUSE, 9p, NFS and CIFS are unsupported.
	switch magic {
	case 0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630:
		return true
	}
	return false
}
func requireLocal(f *os.File) error {
	var fs syscall.Statfs_t
	if e := syscall.Fstatfs(int(f.Fd()), &fs); e != nil {
		return e
	}
	if !localFilesystem(fs.Type) {
		return errors.New("opaque or network filesystem identity unsupported")
	}
	return nil
}
func cleanPath(p string) bool {
	return p != "/" && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

// openDir walks every component with openat/O_NOFOLLOW; checking only the final
// component would permit a symlink swap of a parent before the open.
func openDir(p string) (*os.File, error) {
	if !cleanPath(p) {
		return nil, errors.New("clean absolute directory required")
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		next, err := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), p), nil
}
