package files

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// Faults run in an owned subprocess. A thread-local seccomp filter injects the
// real kernel errno at the FD syscall boundary; no production injection seam.
// Caller must lock its OS thread and terminate the subprocess after the probe.
func injectACLFailure(t *testing.T, op string, errno syscall.Errno) {
	t.Helper()
	call := uintptr(syscall.SYS_FGETXATTR)
	if op == "write" {
		call = syscall.SYS_FSETXATTR
	}
	if op == "remove" {
		call = syscall.SYS_FREMOVEXATTR
	}
	filter := []syscall.SockFilter{
		{Code: 0x20, K: 0},
		{Code: 0x15, K: uint32(call), Jf: 1},
		{Code: 0x06, K: 0x00050000 | uint32(errno)},
		{Code: 0x06, K: 0x7fff0000},
	}
	program := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); e != 0 {
		t.Fatalf("fault injection unavailable (not PASS): %v", e)
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 22, 2, uintptr(unsafe.Pointer(&program)), 0, 0, 0); e != 0 {
		t.Fatalf("fault injection unavailable (not PASS): %v", e)
	}
}

func TestRootACLFailures(t *testing.T) {
	if fault := os.Getenv("BAKABEL_ACL_FAULT"); fault != "" {
		parts := strings.Split(fault, ":")
		n, e := strconv.Atoi(parts[1])
		if e != nil {
			t.Fatal(e)
		}
		want := syscall.Errno(n)
		fd, e := syscall.Open(t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer syscall.Close(fd)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		injectACLFailure(t, parts[0], want)
		switch parts[0] {
		case "read":
			_, e = readRootACLs(fd)
		case "write":
			e = (rootACLs{testACL(), testACL()}).apply(fd)
		case "remove":
			e = (rootACLs{}).apply(fd)
		default:
			t.Fatal("unknown fault", fault)
		}
		if want == syscall.ENODATA {
			if e != nil {
				t.Fatal("ENODATA must mean absent", e)
			}
		} else if !errors.Is(e, want) {
			t.Fatalf("%s silently lost errno: got=%v want=%v", fault, e, want)
		}
		t.Logf("actual syscall %s -> %v", fault, e)
		return
	}
	for _, op := range []string{"read", "write", "remove"} {
		for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.EOPNOTSUPP, syscall.ERANGE, syscall.EIO} {
			fault := fmt.Sprintf("%s:%d", op, errno)
			t.Run(fault, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestRootACLFailures$", "-test.v")
				cmd.Env = append(os.Environ(), "BAKABEL_ACL_FAULT="+fault)
				if out, e := cmd.CombinedOutput(); e != nil {
					t.Fatalf("%v\n%s", e, out)
				} else {
					t.Log(string(out))
				}
			})
		}
	}
}

func TestRootACLDescriptorsStayPinned(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "target")
	for _, p := range []string{source, destination} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	putTestACL(t, source, testAccessACL)
	putTestACL(t, source, testDefaultACL)
	src, e := openDir(source)
	if e != nil {
		t.Fatal(e)
	}
	defer src.Close()
	dst, e := openDir(destination)
	if e != nil {
		t.Fatal(e)
	}
	defer dst.Close()
	for _, p := range []string{source, destination} {
		if e := os.Rename(p, p+"-pinned"); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	acls, e := readRootACLs(int(src.Fd()))
	if e != nil {
		t.Fatal(e)
	}
	if e := acls.apply(int(dst.Fd())); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{testAccessACL, testDefaultACL} {
		if got := aclAt(t, destination+"-pinned", name); !bytes.Equal(got, testACL()) {
			t.Errorf("pinned %s got=%x", name, got)
		}
		if got := aclAt(t, destination, name); len(got) != 0 {
			t.Errorf("replacement path mutated %s", name)
		}
	}
}
