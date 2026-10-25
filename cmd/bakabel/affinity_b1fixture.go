//go:build linux && b1fixture

package main

// Fixture-only CPU confinement for rootless daemons which discard CpusetCpus.
// Excluded from ordinary/release builds. Same compiled fixture binary contains
// both the real _worker and _export implementations; no producer shim exists.
import (
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"
)

func init() {
	runtime.LockOSThread()
	runtime.GOMAXPROCS(2)
	var mask uint64 = 3
	threads, e := os.ReadDir("/proc/self/task")
	if e != nil {
		os.Exit(2)
	}
	for _, thread := range threads {
		tid, e := strconv.Atoi(thread.Name())
		if e != nil {
			os.Exit(2)
		}
		_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, uintptr(tid), unsafe.Sizeof(mask), uintptr(unsafe.Pointer(&mask)))
		if errno != 0 && errno != syscall.ESRCH {
			os.Exit(2)
		}
	}
	runtime.UnlockOSThread()
}
