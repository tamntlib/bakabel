package files

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// ProtectedIdentity contains metadata only, never the protected file's bytes.
// FilesystemPath accounts for bind aliases even when namespace names differ.
type ProtectedIdentity struct {
	Device         uint64 `json:"device"`
	Inode          uint64 `json:"inode"`
	FilesystemPath string `json:"filesystemPath"`
}

// CaptureProtection opens only metadata (O_PATH), including for sockets and
// regular credentials. Every parent is walked without following symlinks.
func CaptureProtection(p string) (ProtectedIdentity, error) {
	var zero ProtectedIdentity
	if !cleanPath(p) {
		return zero, errors.New("invalid protected runtime path")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return zero, err
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if i == len(parts)-1 {
			const oPath = 0x200000 // Linux O_PATH: do not read files or connect sockets.
			flags = oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		}
		next, e := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if e != nil {
			return zero, e
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil {
		return zero, err
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR, syscall.S_IFSOCK:
	case syscall.S_IFREG:
		// A second hard link has no unique backing pathname. Refuse instead of
		// walking every source file or assuming a lexically external link is safe.
		if st.Nlink != 1 {
			return zero, errors.New("hard-linked protected file identity unsupported")
		}
	default:
		return zero, errors.New("unsupported protected runtime object")
	}
	if err = requireLocal(f); err != nil {
		return zero, err
	}
	backing, err := filesystemPath(f)
	if err != nil {
		return zero, err
	}
	return ProtectedIdentity{Device: uint64(st.Dev), Inode: st.Ino, FilesystemPath: backing}, nil
}

func validateProtection(p ProtectedIdentity) error {
	if p.Device == 0 || p.Inode == 0 || p.FilesystemPath != "/" && !cleanPath(p.FilesystemPath) {
		return errors.New("protected runtime identity unavailable")
	}
	return nil
}
