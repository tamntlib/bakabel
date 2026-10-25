//go:build linux

// Package state serializes trusted local launchers and retains durable run ownership.
package state

import (
	"errors"
	"os"
	"sync"
	"syscall"
)

var ErrBusy = errors.New("state launcher guard is held")
var ErrClosed = errors.New("state launcher guard is closed")

// Owner must not be copied. Its methods serialize access within this process.
// Keep it open until run handling is complete; Close is NOT run Release.
type Owner struct {
	mu       sync.Mutex
	dir      *os.File
	lock     *os.File
	syncFile func(*os.File) error
	rename   func(int, string, int, string) error
	poisoned bool
}

// Acquire opens an existing trusted directory and takes a nonblocking Linux flock.
// It intentionally succeeds when owner.json is active/corrupt: recovery may Load it,
// but NewRun cannot replace it. Never remove launcher.lock or recreate dir.
func Acquire(dir string) (*Owner, error) {
	d, err := openDirectory(dir)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(d.Fd()), "launcher.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		d.Close()
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "launcher.lock")
	if err := regularPrivate(lock); err != nil {
		lock.Close()
		d.Close()
		return nil, err
	}
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		d.Close()
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		d.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &Owner{dir: d, lock: lock, syncFile: func(f *os.File) error { return f.Sync() }, rename: syscall.Renameat}, nil
}

// Close releases only the launcher guard. It never removes durable run ownership.
func (o *Owner) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return nil
	}
	err := errors.Join(o.lock.Close(), o.dir.Close())
	o.lock = nil
	o.dir = nil
	return err
}
