package files

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const accessACL = "system.posix_acl_access"
const defaultACL = "system.posix_acl_default"

// Only the two Linux POSIX ACL attributes are promoted here. nil means ENODATA,
// never an unreadable or unsupported ACL. Metadata failure leaves partial output.
type rootACLs [2][]byte

func readRootACLs(fd int) (rootACLs, error) {
	var acls rootACLs
	for i, name := range [2]string{accessACL, defaultACL} {
		p, _ := syscall.BytePtrFromString(name)
		// Linux caps an xattr value at 64 KiB. One bounded read avoids a
		// size-query/allocation race; ERANGE and all non-ENODATA errors fail.
		b := make([]byte, 65536)
		n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
		if errno == syscall.ENODATA {
			continue
		}
		if errno != 0 {
			return rootACLs{}, fmt.Errorf("read root %s: %w", name, errno)
		}
		if n == 0 || n > uintptr(len(b)) {
			return rootACLs{}, errors.New("invalid root POSIX ACL size")
		}
		acls[i] = b[:n]
	}
	return acls, nil
}

func (acls rootACLs) apply(fd int) error {
	for i, name := range [2]string{accessACL, defaultACL} {
		p, _ := syscall.BytePtrFromString(name)
		var errno syscall.Errno
		if len(acls[i]) == 0 {
			_, _, errno = syscall.Syscall(syscall.SYS_FREMOVEXATTR, uintptr(fd), uintptr(unsafe.Pointer(p)), 0)
			if errno == syscall.ENODATA {
				continue
			}
		} else {
			_, _, errno = syscall.Syscall6(syscall.SYS_FSETXATTR, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&acls[i][0])), uintptr(len(acls[i])), 0, 0)
		}
		if errno != 0 {
			return fmt.Errorf("apply root %s: %w", name, errno)
		}
	}
	return nil
}
