package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
)

// The mock is only a recorder of CreateWorker's actual wire configuration.
// Metadata setup, backup, restore and kernel capability enforcement are native.
func fileWorkerCaps(t *testing.T) []string {
	t.Helper()
	var cfg struct {
		HostConfig struct{ CapAdd, CapDrop, SecurityOpt []string }
	}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/create":
			if e := json.NewDecoder(r.Body).Decode(&cfg); e != nil {
				t.Error(e)
			}
			w.Write([]byte(`{"Id":"exact"}`))
		case "/v1.55/containers/exact/json":
			w.Write([]byte(`{"Id":"exact","Name":"/metadata","Config":{"Labels":{"bakabel.worker":"1","bakabel.run":"run","bakabel.daemon":"daemon"}},"HostConfig":{"AutoRemove":false,"RestartPolicy":{"Name":"no"}},"State":{"Status":"created","Running":false,"Restarting":false,"Dead":false,"ExitCode":0}}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(500)
		}
	})
	if _, e := c.CreateWorker(context.Background(), Worker{DaemonID: "daemon", Name: "metadata", RunID: "run"}, WorkerSpec{Image: "fixture", Mode: "workflow", Files: true}); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(cfg.HostConfig.CapDrop, []string{"ALL"}) || !reflect.DeepEqual(cfg.HostConfig.SecurityOpt, []string{"no-new-privileges"}) {
		t.Fatalf("unsafe worker config: %+v", cfg)
	}
	return cfg.HostConfig.CapAdd
}

type workerMetadata struct {
	UID, GID, Mode  uint32
	Access, Default []byte
}
type workerMetadataFixture struct {
	Source, Destination, Repository, Restic, Wrapper, Receipt string
	Snapshot                                                  backup.Snapshot
	Original                                                  map[string]workerMetadata
	Caps                                                      []string
	Mask                                                      uint64
}

const workerAccessACL = "system.posix_acl_access"
const workerDefaultACL = "system.posix_acl_default"

func workerACL(t *testing.T, path, name string) []byte {
	t.Helper()
	b := make([]byte, 65536)
	n, e := syscall.Getxattr(path, name, b)
	if e != nil {
		t.Fatalf("required native ACL read %s %s: %v", path, name, e)
	}
	return b[:n]
}
func workerStat(t *testing.T, path string) workerMetadata {
	t.Helper()
	var st syscall.Stat_t
	if e := syscall.Stat(path, &st); e != nil {
		t.Fatal(e)
	}
	return workerMetadata{st.Uid, st.Gid, st.Mode & 07777, workerACL(t, path, workerAccessACL), workerACL(t, path, workerDefaultACL)}
}
func workerFixtureACL() []byte {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 2)
	// group::--- differs from mask::r-x: a mode-only comparison cannot pass.
	for i, e := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, 1234}, {4, 0, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		o := 4 + i*8
		binary.LittleEndian.PutUint16(b[o:], uint16(e[0]))
		binary.LittleEndian.PutUint16(b[o+2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(b[o+4:], e[2])
	}
	return b
}
func workerCapMask(t *testing.T, caps []string) uint64 {
	t.Helper()
	bits := map[string]uint{"CHOWN": 0, "DAC_OVERRIDE": 1, "DAC_READ_SEARCH": 2, "FOWNER": 3, "FSETID": 4}
	var mask uint64
	for _, c := range caps {
		b, ok := bits[c]
		if !ok {
			t.Fatalf("unhandled production capability %q", c)
		}
		mask |= 1 << b
	}
	return mask
}

// Must run as a privileged fixture parent (Docker defaults + DAC_READ_SEARCH).
// setpriv drops the bounding set BEFORE exec of the Go test helper, so all Go
// threads and every Restic exec receive the actual worker capability set.
func TestFileWorkerRealResticMetadata(t *testing.T) {
	restic := os.Getenv("BAKABEL_FILES_RESTIC")
	if restic == "" {
		t.Skip("opt-in disposable pinned Restic fixture required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("owned UID 0 fixture parent required (not a capability skip)")
	}
	groups, e := os.Getgroups()
	if e != nil {
		t.Fatal(e)
	}
	if os.Getgid() == 2345 {
		t.Fatal("fixture parent belongs to source GID")
	}
	for _, g := range groups {
		if g == 2345 {
			t.Fatal("fixture parent supplementary source GID")
		}
	}
	status, e := os.ReadFile("/proc/self/status")
	if e != nil {
		t.Fatal(e)
	}
	var parentEffective uint64
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:\t"); ok {
			parentEffective, e = strconv.ParseUint(v, 16, 64)
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	if parentEffective&(1<<4) == 0 {
		t.Fatal("fixture parent requires FSETID to freeze a genuine original SGID oracle")
	}
	t.Logf("fixture parent uid/gid=%d/%d groups=%v CapEff=%016x (FSETID available before backup)", os.Geteuid(), os.Getegid(), groups, parentEffective)
	b, e := os.ReadFile(restic)
	if e != nil {
		t.Fatal(e)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != "01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6" {
		t.Fatalf("pinned Restic mismatch: %s", got)
	}
	root := t.TempDir()
	f := workerMetadataFixture{Source: files.WorkerPath(root, "/data"), Destination: filepath.Join(root, "restore"), Repository: filepath.Join(root, "repo"), Restic: restic, Wrapper: filepath.Join(root, "restic-receipt"), Receipt: filepath.Join(root, "restic-status"), Caps: fileWorkerCaps(t), Original: map[string]workerMetadata{}}
	f.Mask = workerCapMask(t, f.Caps)
	for _, rel := range []string{".", "nested"} {
		p := filepath.Join(f.Source, rel)
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(p, 4321, 2345); e != nil {
			t.Fatal(e)
		}
		if e := syscall.Chmod(p, 02750); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{workerAccessACL, workerDefaultACL} {
			if e := syscall.Setxattr(p, name, workerFixtureACL(), 0); e != nil {
				t.Fatalf("required fixture ACL: %v", e)
			}
		}
		f.Original[rel] = workerStat(t, p)
		if got := f.Original[rel]; got.UID != 4321 || got.GID != 2345 || got.Mode != 02750 {
			t.Fatalf("source precondition (not SGID regression): %s %+v", rel, got)
		}
	}
	if e := os.WriteFile(filepath.Join(f.Source, "nested", "payload"), []byte("original-source-oracle\n"), 0600); e != nil {
		t.Fatal(e)
	}
	env := append(os.Environ(), "RESTIC_REPOSITORY="+f.Repository, "RESTIC_PASSWORD=disposable-worker-metadata")
	cmd := exec.Command(restic, "--no-cache", "init")
	cmd.Env = env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("init: %v\n%s", e, out)
	}
	r := backup.Repository{Binary: restic, Env: env}
	m, e := files.Capture("install", root, files.Volume{DaemonID: "daemon", NodeID: "node", Name: "volume", Mountpoint: f.Source, Destination: "/data"}, f.Source)
	if e != nil {
		t.Fatal(e)
	}
	result := r.Backup(context.Background(), m, "worker-metadata", files.Hostname("install"), []string{"--group-by", "host,paths", "--", f.Source})
	if result.Err != nil || result.Status != "complete" {
		t.Fatalf("backup: %+v", result)
	}
	snapshots, e := r.Snapshots(context.Background())
	if e != nil || len(snapshots) != 1 {
		t.Fatal(snapshots, e)
	}
	f.Snapshot = snapshots[0]
	// Freeze original source metadata, never derive expectations from Restic stage.
	for rel, want := range f.Original {
		if got := workerStat(t, filepath.Join(f.Source, rel)); !reflect.DeepEqual(got, want) {
			t.Fatalf("source changed during backup: %s", rel)
		}
	}
	if e := os.Mkdir(f.Destination, 0700); e != nil {
		t.Fatal(e)
	}
	var src, dst syscall.Stat_t
	if e := syscall.Stat(f.Source, &src); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Stat(f.Destination, &dst); e != nil {
		t.Fatal(e)
	}
	if src.Dev == dst.Dev && src.Ino == dst.Ino {
		t.Fatal("destination aliases live source")
	}
	t.Logf("original oracle=%+v; distinct live source=%d/%d destination=%d/%d snapshot=%s", f.Original, src.Dev, src.Ino, dst.Dev, dst.Ino, f.Snapshot.ID)
	if e := os.RemoveAll(f.Source); e != nil {
		t.Fatal(e)
	}
	// This test-only shell records the status inherited immediately before exec
	// of the hash-checked real Restic, not an impersonated Restic implementation.
	script := "#!/bin/sh\nset -eu\nwhile IFS= read -r line; do printf '%s\\n' \"$line\"; done < /proc/self/status >> \"" + f.Receipt + "\"\nexec \"" + restic + "\" \"$@\"\n"
	if e := os.WriteFile(f.Wrapper, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	fixture := filepath.Join(root, "fixture.json")
	data, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(fixture, data, 0600); e != nil {
		t.Fatal(e)
	}
	names := []string{"-all"}
	for _, c := range f.Caps {
		names = append(names, "+"+strings.ToLower(c))
	}
	cmd = exec.Command("/usr/bin/setpriv", "--bounding-set="+strings.Join(names, ","), "--no-new-privs", os.Args[0], "-test.run=^TestFileWorkerResticMetadataHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "BAKABEL_TEST_WORKER_METADATA="+fixture)
	out, e := cmd.CombinedOutput()
	t.Logf("CreateWorker caps=%v mask=%016x; native helper:\n%s", f.Caps, f.Mask, out)
	if e != nil {
		t.Fatalf("production-capability restore regression: %v", e)
	}
}

func workerStatus(t *testing.T, data []byte, mask uint64) {
	t.Helper()
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			values[k] = strings.TrimSpace(v)
		}
	}
	for _, key := range []string{"Uid", "Gid"} {
		if strings.Join(strings.Fields(values[key]), ",") != "0,0,0,0" {
			t.Fatalf("%s=%q", key, values[key])
		}
	}
	for _, group := range strings.Fields(values["Groups"]) {
		if group == "2345" {
			t.Fatal("worker unexpectedly belongs to source GID")
		}
	}
	if values["NoNewPrivs"] != "1" {
		t.Fatalf("NNP=%s", values["NoNewPrivs"])
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"} {
		want := mask
		if key == "CapInh" || key == "CapAmb" {
			want = 0
		}
		got, e := strconv.ParseUint(values[key], 16, 64)
		if e != nil || got != want {
			t.Fatalf("%s got=%s want=%016x err=%v", key, values[key], want, e)
		}
	}
	t.Logf("native status UID=%s GID=%s groups=%q Eff=%s Prm=%s Bnd=%s NNP=%s", values["Uid"], values["Gid"], values["Groups"], values["CapEff"], values["CapPrm"], values["CapBnd"], values["NoNewPrivs"])
}

func TestFileWorkerResticMetadataHelper(t *testing.T) {
	fixture := os.Getenv("BAKABEL_TEST_WORKER_METADATA")
	if fixture == "" {
		t.Skip("owned subprocess helper only")
	}
	var f workerMetadataFixture
	data, e := os.ReadFile(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(data, &f); e != nil {
		t.Fatal(e)
	}
	if f.Mask != workerCapMask(t, f.Caps) {
		t.Fatal("fixture capability mismatch")
	}
	tasks, e := filepath.Glob("/proc/self/task/*/status")
	if e != nil || len(tasks) == 0 {
		t.Fatal("native task status unavailable", e)
	}
	for _, p := range tasks {
		status, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		workerStatus(t, status, f.Mask)
	}
	if _, e := os.Stat(f.Source); !os.IsNotExist(e) {
		t.Fatal("original source must be absent before restore", e)
	}
	r := backup.Repository{Binary: f.Wrapper, Env: append(os.Environ(), "RESTIC_REPOSITORY="+f.Repository, "RESTIC_PASSWORD=disposable-worker-metadata")}
	target, e := files.OpenRestore(f.Snapshot, f.Destination, []string{f.Repository})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if e := target.Restore(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	receipt, e := os.ReadFile(f.Receipt)
	if e != nil {
		t.Fatal(e)
	}
	workerStatus(t, receipt, f.Mask)
	for rel, want := range f.Original {
		p := filepath.Join(f.Destination, rel)
		got := workerStat(t, p)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ORIGINAL SOURCE metadata %s got uid/gid/mode=%d/%d/%04o access=%x default=%x; want=%d/%d/%04o access=%x default=%x", rel, got.UID, got.GID, got.Mode, got.Access, got.Default, want.UID, want.GID, want.Mode, want.Access, want.Default)
		}
		child := filepath.Join(p, "post-restore-child")
		if e := os.Mkdir(child, 0777); e != nil {
			t.Fatal(e)
		}
		inherited := workerStat(t, child)
		if inherited.UID != uint32(os.Geteuid()) || inherited.GID != want.GID || inherited.Mode != want.Mode || !bytes.Equal(inherited.Access, want.Default) || !bytes.Equal(inherited.Default, want.Default) {
			t.Errorf("ORIGINAL SOURCE inheritance %s got gid/mode=%d/%04o access=%x default=%x; want gid=%d SGID + original default=%x", rel, inherited.GID, inherited.Mode, inherited.Access, inherited.Default, want.GID, want.Default)
		}
		t.Logf("restored %s uid/gid/mode=%d/%d/%04o child gid/mode=%d/%04o", rel, got.UID, got.GID, got.Mode, inherited.GID, inherited.Mode)
	}
	payload, e := os.ReadFile(filepath.Join(f.Destination, "nested", "payload"))
	if e != nil || string(payload) != "original-source-oracle\n" {
		t.Fatal("payload mismatch", e)
	}
}
