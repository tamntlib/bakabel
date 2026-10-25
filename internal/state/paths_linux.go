//go:build linux

package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrUnsafePath = errors.New("state path must be a trusted private regular file/directory without symlinks")

// Walk from / through descriptors: O_NOFOLLOW on just the final component is insufficient.
// The caller provisions the directory; we never mkdir, remove, or replace it.
func openDirectory(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(absolute, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "state-directory")
	var st syscall.Stat_t
	if e := syscall.Fstat(fd, &st); e != nil {
		f.Close()
		return nil, e
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		f.Close()
		return nil, ErrUnsafePath
	}
	return f, nil
}
func checkTarget(dir *os.File, name string) error {
	fd, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(e, syscall.ENOENT) {
		return nil
	}
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return regularPrivate(f)
}
func regularPrivate(f *os.File) error {
	var st syscall.Stat_t
	if e := syscall.Fstat(int(f.Fd()), &st); e != nil {
		return e
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return ErrUnsafePath
	}
	return nil
}
