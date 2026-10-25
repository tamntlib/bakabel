//go:build linux

package state

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"
)

var ErrUncertain = errors.New("state write failed; close guard and recover before further mutation")

// atomicWrite is called only while holding Owner.mu and the launcher flock.
// A fixed exclusive pending entry bounds crash residue; it is never auto-adopted.
func (o *Owner) atomicWrite(name string, value any) (err error) {
	defer func() {
		if err != nil {
			o.poisoned = true
		}
	}()
	if err = checkTarget(o.dir, name); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	limit := MaxRecordBytes
	if name == "last-result.json" {
		limit = MaxResultBytes
	}
	if len(b) > limit {
		return ErrInvalid
	}
	fd, err := syscall.Openat(int(o.dir.Fd()), ".pending", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), ".pending")
	defer func() {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		if e := syscall.Unlinkat(int(o.dir.Fd()), ".pending"); e != nil && !errors.Is(e, syscall.ENOENT) {
			err = errors.Join(err, e)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = o.syncFile(f); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		f = nil
		return err
	}
	f = nil
	if err = o.rename(int(o.dir.Fd()), ".pending", int(o.dir.Fd()), name); err != nil {
		return err
	}
	return o.syncFile(o.dir)
}
