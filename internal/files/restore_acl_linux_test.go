package files

import (
	"bytes"
	"context"
	aclBinary "encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
)

const testAccessACL = "system.posix_acl_access"
const testDefaultACL = "system.posix_acl_default"

// Linux POSIX ACL v2: owner rwx, named uid 1234 r-x, owning group ---,
// mask r-x, other ---. stat's group bits are the MASK, not group::.
func testACL() []byte {
	b := make([]byte, 4+5*8)
	aclBinary.LittleEndian.PutUint32(b, 2)
	for i, e := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, 1234}, {4, 0, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		o := 4 + i*8
		aclBinary.LittleEndian.PutUint16(b[o:], uint16(e[0]))
		aclBinary.LittleEndian.PutUint16(b[o+2:], uint16(e[1]))
		aclBinary.LittleEndian.PutUint32(b[o+4:], e[2])
	}
	return b
}

func aclAt(t *testing.T, path, name string) []byte {
	t.Helper()
	b := make([]byte, 65536)
	n, e := syscall.Getxattr(path, name, b)
	if errors.Is(e, syscall.ENODATA) {
		return nil
	}
	if e != nil {
		t.Fatalf("ACL read %s %s (unsupported is NOT a pass): %v", path, name, e)
	}
	return b[:n]
}

func putTestACL(t *testing.T, path, name string) {
	t.Helper()
	if e := syscall.Setxattr(path, name, testACL(), 0); e != nil {
		t.Fatalf("ACL fixture unavailable (not a PASS): %v", e)
	}
}

func effectiveRootAccess(t *testing.T, path string, hasACL bool) {
	t.Helper()
	f, e := openDir(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, subject := range []struct {
		name     string
		uid, gid uint32
		allowed  bool
	}{
		{"named-user", 1234, 3456, hasACL}, {"owning-group", 3456, 2345, !hasACL}, {"stale-named-user", 2222, 3456, false},
	} {
		cmd := exec.Command("/bin/sh", "-c", "cd /proc/self/fd/3 && cat payload")
		cmd.ExtraFiles = []*os.File{f}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: subject.uid, Gid: subject.gid, Groups: []uint32{}}}
		out, e := cmd.CombinedOutput()
		if subject.allowed != (e == nil) || (e == nil && string(out) != "ACL fixture\n") {
			t.Errorf("effective %s allowed=%v: err=%v output=%q", subject.name, subject.allowed, e, out)
		}
		t.Logf("effective %s uid=%d gid=%d allowed=%v actual-success=%v", subject.name, subject.uid, subject.gid, subject.allowed, e == nil)
	}
}

// Runs actual Capture -> Repository.Backup/finalize -> exact snapshot restore ->
// RestoreTarget.Restore. Neither the oracle nor production staging is synthetic.
func TestRealResticRootACL(t *testing.T) {
	for _, c := range []struct {
		name                 string
		sourceACL, targetACL bool
	}{
		{"source-acl-clean-target", true, false},
		{"source-acl-stale-target", true, true},
		{"no-acl-clean-target", false, false},
		{"no-acl-stale-target", false, true},
	} {
		t.Run(c.name, func(t *testing.T) { realRootACLRoundTrip(t, c.sourceACL, c.targetACL) })
	}
}

func TestRealResticRestoreACLErrors(t *testing.T) {
	if os.Getenv("BAKABEL_FILES_RESTIC") == "" {
		t.Skip("opt-in disposable pinned Restic fixture required")
	}
	if fault := os.Getenv("BAKABEL_RESTORE_ACL_FAULT"); fault != "" {
		realRootACLRoundTrip(t, fault != "remove", true)
		return
	}
	for _, op := range []string{"read", "write", "remove"} {
		t.Run(op, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRealResticRestoreACLErrors$", "-test.v")
			cmd.Env = append(os.Environ(), "BAKABEL_RESTORE_ACL_FAULT="+op)
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("%v\n%s", e, out)
			} else {
				t.Log(string(out))
			}
		})
	}
}

func realRootACLRoundTrip(t *testing.T, sourceACL, targetACL bool) {
	binary := os.Getenv("BAKABEL_FILES_RESTIC")
	if binary == "" {
		t.Skip("opt-in disposable pinned Restic fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned root fixture required for effective-identity probes")
	}
	ctx := context.Background()
	root := t.TempDir()
	source := WorkerPath(root, "/data")
	if e := os.MkdirAll(source, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(source)
	if e := os.Chown(source, 4321, 2345); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Chmod(source, 02750); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(source, "payload"), []byte("ACL fixture\n"), 0644); e != nil {
		t.Fatal(e)
	}
	// CI uses umask 0077. Make the payload readable explicitly so these
	// probes measure the directory ACL, not incidental payload permissions.
	if e := os.Chmod(filepath.Join(source, "payload"), 0644); e != nil {
		t.Fatal(e)
	}
	if sourceACL {
		putTestACL(t, source, testAccessACL)
		putTestACL(t, source, testDefaultACL)
	}
	wantAccess, wantDefault := aclAt(t, source, testAccessACL), aclAt(t, source, testDefaultACL)
	effectiveRootAccess(t, source, sourceACL)
	var wantStat syscall.Stat_t
	if e := syscall.Stat(source, &wantStat); e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(root, "repo")
	env := append(os.Environ(), "RESTIC_REPOSITORY="+repo, "RESTIC_PASSWORD=disposable-acl-fixture")
	cmd := exec.Command(binary, "--no-cache", "init")
	cmd.Env = env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	r := backup.Repository{Binary: binary, Env: env}
	m, e := Capture("install", root, Volume{"daemon", "node", "volume", source, "/data"}, source)
	if e != nil {
		t.Fatal(e)
	}
	result := r.Backup(ctx, m, "acl-roundtrip", Hostname("install"), []string{"--group-by", "host,paths", "--", source})
	if result.Err != nil || result.Status != "complete" {
		t.Fatal(result)
	}
	all, e := r.Snapshots(ctx)
	if e != nil || len(all) != 1 {
		t.Fatal(all, e)
	}
	s := all[0]
	if e := os.RemoveAll(source); e != nil {
		t.Fatal(e)
	}
	oracleParent := filepath.Join(root, "native-restic-oracle")
	oracle := filepath.Join(oracleParent, filepath.Base(m.Paths[0]))
	cmd = exec.Command(binary, "--no-cache", "restore", s.ID+":"+filepath.Dir(m.Paths[0]), "--include", "/"+filepath.Base(m.Paths[0]), "--target", oracleParent, "--verify")
	cmd.Env = env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	for name, want := range map[string][]byte{testAccessACL: wantAccess, testDefaultACL: wantDefault} {
		if got := aclAt(t, oracle, name); !bytes.Equal(got, want) {
			t.Fatalf("Restic oracle lost original %s: got=%x want=%x", name, got, want)
		}
	}
	t.Logf("original source gone; native Restic exact snapshot=%s access=%x default=%x", s.ID, wantAccess, wantDefault)
	dest := filepath.Join(root, "restore")
	if e := os.Mkdir(dest, 0700); e != nil {
		t.Fatal(e)
	}
	if targetACL {
		stale := testACL()
		aclBinary.LittleEndian.PutUint32(stale[16:], 2222)
		for _, name := range []string{testAccessACL, testDefaultACL} {
			if e := syscall.Setxattr(dest, name, stale, 0); e != nil {
				t.Fatal(e)
			}
		}
	}
	target, e := OpenRestore(s, dest, []string{repo})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	moved := filepath.Join(root, "pinned")
	if e := os.Rename(dest, moved); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(oracle, dest); e != nil {
		t.Fatal(e)
	}
	if fault := os.Getenv("BAKABEL_RESTORE_ACL_FAULT"); fault != "" {
		want := syscall.EPERM
		if fault == "read" {
			want = syscall.EOPNOTSUPP
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		injectACLFailure(t, fault, want)
		e := target.Restore(ctx, r)
		if !errors.Is(e, want) {
			t.Fatalf("actual Restore %s error got=%v want=%v", fault, e, want)
		}
		t.Logf("actual Restore failed closed on %s: %v", fault, e)
		return
	}
	if e := target.Restore(ctx, r); e != nil {
		t.Fatal(e)
	}
	for name, want := range map[string][]byte{testAccessACL: wantAccess, testDefaultACL: wantDefault} {
		if got := aclAt(t, moved, name); !bytes.Equal(got, want) {
			t.Errorf("promoted root %s lost: got=%x want=%x", name, got, want)
		}
		if got := aclAt(t, oracle, name); !bytes.Equal(got, want) {
			t.Errorf("swapped path mutated %s", name)
		}
	}
	var gotStat syscall.Stat_t
	if e := syscall.Stat(moved, &gotStat); e != nil {
		t.Fatal(e)
	}
	if gotStat.Uid != wantStat.Uid || gotStat.Gid != wantStat.Gid || gotStat.Mode&07777 != wantStat.Mode&07777 {
		t.Errorf("root stat got uid/gid/mode=%d/%d/%o want=%d/%d/%o", gotStat.Uid, gotStat.Gid, gotStat.Mode&07777, wantStat.Uid, wantStat.Gid, wantStat.Mode&07777)
	}
	effectiveRootAccess(t, moved, sourceACL)
	inherited := filepath.Join(moved, "post-restore-child")
	if e := os.Mkdir(inherited, 0777); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{testAccessACL, testDefaultACL} {
		if got := aclAt(t, inherited, name); !bytes.Equal(got, wantDefault) {
			t.Errorf("post-restore default inheritance %s got=%x want=%x", name, got, wantDefault)
		}
	}
}
