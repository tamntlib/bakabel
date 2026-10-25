//go:build linux

// Package integration exercises real disposable engines and repositories. It
// never substitutes Engine/S3 responses. See fixtures/README.md for isolation.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/restore"
)

const image = "postgres:18.6-alpine3.24"
const socket = "/var/run/docker.sock"
const artifacts = "/fixture/artifacts"
const binary = "/fixture/bin/integration.test"

func repository() backup.Repository {
	return backup.Repository{Binary: "/fixture/bin/restic", Env: []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "GOMAXPROCS=2", "HOME=/nonexistent",
		"RESTIC_REPOSITORY=s3:http://127.0.0.1:9000/bakabel-fixture/repository", "RESTIC_PASSWORD_FILE=/credentials/restic-password",
		"AWS_SHARED_CREDENTIALS_FILE=/credentials/aws", "AWS_PROFILE=default", "AWS_DEFAULT_REGION=us-east-1",
	}}
}

type fileJob struct {
	Action, Source, Run, Destination string
	Volume                           files.Volume
	Snapshot                         backup.Snapshot
}

// TestMain provides the actual executable producer Restic invokes. No testing
// banners or stderr are ever mixed into pg_dump stdout.
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "fixture-exec" {
		// Fixture-only pre-exec affinity, not a source cancellation agent.
		// Rootless cpuset cgroups are unavailable; pin after runc's reset.
		runtime.LockOSThread()
		mask := uintptr(3)
		_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0, unsafe.Sizeof(mask), uintptr(unsafe.Pointer(&mask)))
		if errno != 0 {
			fmt.Fprintln(os.Stderr, errno)
			os.Exit(2)
		}
		if e := syscall.Exec(os.Args[2], os.Args[2:], os.Environ()); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
	}
	if p := os.Getenv("BAKABEL_B3_DUMP_FILE"); p != "" {
		var d docker.Dump
		b, e := os.ReadFile(p)
		if e != nil || json.Unmarshal(b, &d) != nil {
			os.Exit(2)
		}
		c, e := docker.NewClient(socket)
		if e != nil {
			os.Exit(2)
		}
		code, e := c.StreamDump(context.Background(), d, os.Stdout)
		if e != nil && code == 0 {
			code = 1
		}
		os.Exit(code)
	}
	if p := os.Getenv("BAKABEL_B3_FILE_JOB"); p != "" {
		var j fileJob
		b, e := os.ReadFile(p)
		if e != nil || json.Unmarshal(b, &j) != nil {
			os.Exit(2)
		}
		e = runFileJob(j)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func writeJSON(p string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	return errors.Join(e, ce)
}

func runFileJob(j fileJob) error {
	r := repository()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if j.Action == "restore" {
		t, e := files.OpenRestore(j.Snapshot, j.Destination, []string{"/credentials"})
		if e != nil {
			return e
		}
		defer t.Close()
		return t.Restore(ctx, r)
	}
	p := files.WorkerPath(j.Source, j.Volume.Destination)
	metadata, e := files.Capture("b3fixture", j.Source, j.Volume, p)
	if e != nil {
		return e
	}
	if j.Action == "unknown" {
		r.VerifySource = func(context.Context) error { return errors.New("fixture postflight rejected") }
	}
	result := files.Backup(ctx, r, metadata, j.Run, "b3fixture", []string{"/credentials"})
	expected := "complete"
	if j.Action == "partial" {
		expected = "partial"
	}
	if j.Action == "unknown" {
		expected = "unknown"
	}
	if result.Status != expected || result.SnapshotID == "" || (expected == "complete") != (result.Err == nil) {
		return fmt.Errorf("file result status=%s id=%s err=%v", result.Status, result.SnapshotID, result.Err)
	}
	if expected == "partial" && !strings.Contains(result.Err.Error(), "exit 3") {
		return fmt.Errorf("partial was not actual Restic unreadable-file exit 3: %v", result.Err)
	}
	all, e := r.Snapshots(ctx)
	if e != nil {
		return e
	}
	for _, s := range all {
		if s.ID == result.SnapshotID {
			_, e = s.Restorable()
			if (expected == "complete") != (e == nil) {
				return fmt.Errorf("incorrect restore gate for %s", expected)
			}
			receipt := filepath.Join(artifacts, j.Run+".snapshot.json")
			if e := writeJSON(receipt, s); e != nil {
				return e
			}
			return os.Chmod(receipt, 0644) // public synthetic metadata, not credentials/checkpoints
		}
	}
	return errors.New("exact file snapshot missing")
}

type fixture struct {
	t    *testing.T
	ctx  context.Context
	c    *docker.Client
	http *http.Client
}

func realFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getenv("BAKABEL_B3_OPT_IN") != "isolated" {
		t.Skip("run fixtures/run.py; real isolated Swarm+MinIO opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	t.Cleanup(cancel)
	c, e := docker.NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{t: t, ctx: ctx, c: c, http: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}}
	info, e := c.Info(ctx)
	if e != nil || info.ID == os.Getenv("BAKABEL_B3_OUTER_DAEMON_ID") || !info.Swarm.ControlAvailable {
		t.Fatalf("not isolated real manager: %+v %v", info, e)
	}
	t.Logf("isolated daemon=%s node=%s outer=%s", info.ID, info.Swarm.NodeID, os.Getenv("BAKABEL_B3_OUTER_DAEMON_ID"))
	return f
}
func (f *fixture) api(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(f.ctx, method, "http://docker/v1.55"+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	r, e := f.http.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return fmt.Errorf("Engine %s %s status=%d", method, path, r.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}
func (f *fixture) mustAPI(method, path string, in, out any) {
	f.t.Helper()
	if e := f.api(method, path, in, out); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fixture) run(s docker.Source, argv ...string) string {
	f.t.Helper()
	id, e := f.c.CreateExec(f.ctx, s.ContainerID, docker.ExecConfig{User: "0", Cmd: argv})
	if e != nil {
		f.t.Fatal(e)
	}
	var out, stderr bytes.Buffer
	e = f.c.StartExec(f.ctx, id, &out, &stderr)
	code, w := f.c.WaitExec(f.ctx, id)
	if e != nil || w != nil || code != 0 {
		f.t.Fatalf("exec code=%d stream=%v wait=%v stderr=%s", code, e, w, stderr.String())
	}
	return strings.TrimSpace(out.String())
}
func (f *fixture) sql(s docker.Source, db, q string) string {
	f.t.Helper()
	conn := "host='/var/run/postgresql' user='postgres' dbname='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(db) + "'"
	return f.run(s, "psql", "-XAt", "-v", "ON_ERROR_STOP=1", "--dbname", conn, "--command", q)
}
func (f *fixture) ready(s docker.Source) {
	f.t.Helper()
	for i := 0; i < 100; i++ {
		id, e := f.c.CreateExec(f.ctx, s.ContainerID, docker.ExecConfig{User: "0", Cmd: []string{"sh", "-c", `test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres`}})
		if e == nil {
			e = f.c.StartExec(f.ctx, id, io.Discard, io.Discard)
			code, w := f.c.WaitExec(f.ctx, id)
			if e == nil && w == nil && code == 0 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.t.Fatal("Postgres readiness timeout")
}
func (f *fixture) removeService(id string) {
	f.t.Helper()
	f.mustAPI("DELETE", "/services/"+id, nil, nil)
	var v any
	if e := f.api("GET", "/services/"+id, nil, &v); e == nil {
		f.t.Fatal("service cleanup readback still present")
	}
}
func (f *fixture) service(name, kind, path, mode string, replicas uint64, constraints []string) string {
	f.t.Helper()
	if len(constraints) == 0 {
		info, e := f.c.Info(f.ctx)
		if e != nil {
			f.t.Fatal(e)
		}
		constraints = []string{"node.id==" + info.Swarm.NodeID}
	}
	labels := map[string]string{"com.docker.stack.namespace": "b3fixture"}
	if kind != "" {
		labels["bakabel.type"] = kind
	}
	if path != "" {
		labels["bakabel.paths"] = path
	}
	spec := map[string]any{"Image": image, "Env": []string{"POSTGRES_USER=postgres", "POSTGRES_DB=fixture", "POSTGRES_HOST_AUTH_METHOD=trust"}, "Command": []string{binary}, "Args": []string{"fixture-exec", "/usr/local/bin/docker-entrypoint.sh", "postgres"}, "Mounts": []map[string]any{bind("/fixture/bin", "/fixture/bin", true)}}
	if kind != "postgres" {
		spec["Args"] = []string{"fixture-exec", "/bin/sh", "-c", "exec sleep infinity"}
		spec["Mounts"] = []map[string]any{bind("/fixture/bin", "/fixture/bin", true), {"Type": "volume", "Source": "b3-files", "Target": "/data", "ReadOnly": false, "VolumeOptions": map[string]any{"NoCopy": true}}}
	}
	modes := map[string]any{"Replicated": map[string]any{"Replicas": replicas}}
	if mode == "global" {
		modes = map[string]any{"Global": map[string]any{}}
	}
	var out struct{ ID string }
	f.mustAPI("POST", "/services/create", map[string]any{"Name": "b3fixture_" + name, "Labels": labels, "TaskTemplate": map[string]any{"ContainerSpec": spec, "Networks": []map[string]string{{"Target": "host"}}, "Placement": map[string]any{"Constraints": constraints}, "RestartPolicy": map[string]any{"Condition": "none"}}, "Mode": modes}, &out)
	id := out.ID
	f.t.Cleanup(func() {
		old := f.ctx
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		f.ctx = ctx
		defer func() { f.ctx = old }()
		var v any
		if f.api("GET", "/services/"+id, nil, &v) == nil {
			f.removeService(id)
		}
	})
	return id
}
func (f *fixture) discover() ([]docker.Target, error) {
	return f.c.Discover(f.ctx, docker.DiscoveryOptions{Installation: "b3fixture", Platform: "swarm", Scope: []string{"b3fixture"}, DockerSocket: socket, StateDir: "/var/lib/bakabel", PasswordFile: "/credentials/restic-password", S3CredentialsFile: "/credentials/aws", Repository: "s3:http://127.0.0.1:9000/bakabel-fixture/repository"})
}
func (f *fixture) targets(n int) []docker.Target {
	f.t.Helper()
	for i := 0; i < 100; i++ {
		all, e := f.discover()
		if e == nil && len(all) == n {
			return all
		}
		time.Sleep(100 * time.Millisecond)
	}
	all, e := f.discover()
	f.t.Fatalf("discovery wanted %d got %+v err=%v", n, all, e)
	return nil
}
func bind(src, dst string, ro bool) map[string]any {
	return map[string]any{"Type": "bind", "Source": src, "Target": dst, "ReadOnly": ro}
}
func volume(src, dst string, ro bool) map[string]any {
	return map[string]any{"Type": "volume", "Source": src, "Target": dst, "ReadOnly": ro, "VolumeOptions": map[string]any{"NoCopy": true}}
}
func (f *fixture) container(name string, cfg map[string]any) docker.Source {
	f.t.Helper()
	var out struct {
		ID string `json:"Id"`
	}
	f.mustAPI("POST", "/containers/create?name="+name, cfg, &out)
	f.t.Cleanup(func() {
		old := f.ctx
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		f.ctx = ctx
		defer func() { f.ctx = old }()
		var v any
		if f.api("GET", "/containers/"+out.ID+"/json", nil, &v) == nil {
			f.mustAPI("DELETE", "/containers/"+out.ID+"?force=true&v=true", nil, nil)
			if f.api("GET", "/containers/"+out.ID+"/json", nil, &v) == nil {
				f.t.Error("container cleanup readback still present")
			}
		}
	})
	f.mustAPI("POST", "/containers/"+out.ID+"/start", nil, nil)
	s, e := f.c.CaptureSource(f.ctx, out.ID)
	if e != nil {
		f.t.Fatal(e)
	}
	return s
}
func (f *fixture) fileWorker(j fileJob, readonlyMount bool, user string) backup.Snapshot {
	f.t.Helper()
	job := filepath.Join(artifacts, j.Run+".job.json")
	if e := writeJSON(job, j); e != nil {
		f.t.Fatal(e)
	}
	if e := os.Chmod(job, 0644); e != nil {
		f.t.Fatal(e)
	}
	mounts := []map[string]any{bind("/fixture/bin", "/fixture/bin", true), bind("/fixture/artifacts", artifacts, false), bind("/fixture/secrets", "/credentials", true)}
	if readonlyMount {
		mounts = append(mounts, volume(j.Volume.Name, files.WorkerPath(j.Source, j.Volume.Destination), true))
	}
	if j.Action == "restore" {
		mounts = append(mounts, bind("/fixture/destination", j.Destination, false))
	}
	s := f.container("b3-"+j.Run, map[string]any{"Image": image, "Entrypoint": []string{binary}, "Cmd": []string{"fixture-exec", binary}, "User": user, "Env": []string{"BAKABEL_B3_FILE_JOB=" + job, "GOMAXPROCS=2"}, "HostConfig": map[string]any{"NetworkMode": "host", "Mounts": mounts, "RestartPolicy": map[string]string{"Name": "no"}}})
	var out struct{ StatusCode int }
	f.mustAPI("POST", "/containers/"+s.ContainerID+"/wait?condition=not-running", nil, &out)
	inspected, e := f.c.InspectContainer(f.ctx, s.ContainerID)
	if e != nil {
		f.t.Fatal(e)
	}
	credentialRO, sourceRO := false, !readonlyMount
	for _, m := range inspected.Mounts {
		if m.Destination == "/credentials" && !m.RW {
			credentialRO = true
		}
		if readonlyMount && m.Destination == files.WorkerPath(j.Source, j.Volume.Destination) && !m.RW {
			sourceRO = true
		}
	}
	if !credentialRO || !sourceRO {
		f.t.Fatal("worker credential/source read-only mount not verified")
	}
	if e := writeJSON(filepath.Join(artifacts, j.Run+".inspect.json"), inspected); e != nil {
		f.t.Fatal(e)
	}
	if out.StatusCode != 0 {
		f.t.Fatalf("file worker %s code=%d (inspect container logs)", j.Run, out.StatusCode)
	}
	if j.Action == "restore" {
		return j.Snapshot
	}
	var snap backup.Snapshot
	b, e := os.ReadFile(filepath.Join(artifacts, j.Run+".snapshot.json"))
	if e != nil || json.Unmarshal(b, &snap) != nil {
		f.t.Fatal("snapshot receipt", e)
	}
	return snap
}

func TestSwarmServiceMetadataAndPlacement(t *testing.T) {
	f := realFixture(t)
	f.targets(0)
	pgid := f.service("pg", "postgres", "", "replicated", 1, nil)
	all := f.targets(1)
	src := all[0].Source
	f.ready(src)
	v, e := f.c.InspectContainer(f.ctx, src.ContainerID)
	if e != nil {
		t.Fatal(e)
	}
	if v.Config.Labels["bakabel.type"] != "" {
		t.Fatal("fixture accidentally used container opt-in label")
	}
	t.Logf("deploy/service labels selected PG container=%s; task opt-in absent", src.ContainerID)
	fid := f.service("files", "volume", "/data", "replicated", 1, nil)
	f.targets(2)
	f.removeService(fid)
	f.targets(1)
	f.removeService(pgid)
	f.targets(0)
	for _, tc := range []struct {
		name, kind, path, mode string
		n                      uint64
		constraints            []string
	}{
		{"zero", "postgres", "", "replicated", 0, nil}, {"two", "postgres", "", "replicated", 2, nil}, {"global", "volume", "/data", "global", 0, nil},
		{"offnode", "postgres", "", "replicated", 1, []string{"node.id==nonexistent-fixture-node"}},
		{"badtype", "unsupported", "", "replicated", 1, nil}, {"traversal", "volume", "/data/../etc", "replicated", 1, nil}, {"missingmount", "volume", "/missing", "replicated", 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := f.service(tc.name, tc.kind, tc.path, tc.mode, tc.n, tc.constraints)
			defer f.removeService(id)
			if tc.name == "traversal" || tc.name == "missingmount" {
				f.waitRunningTask(id)
			} else {
				time.Sleep(200 * time.Millisecond)
			}
			if _, e := f.discover(); e == nil {
				t.Fatal("unsupported real service accepted")
			}
			t.Log("real service rejected", tc.name)
		})
	}
}

func (f *fixture) waitRunningTask(service string) {
	f.t.Helper()
	for i := 0; i < 100; i++ {
		var tasks []struct {
			ServiceID string
			Status    struct{ State string }
		}
		f.mustAPI("GET", "/tasks", nil, &tasks)
		for _, task := range tasks {
			if task.ServiceID == service && task.Status.State == "running" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.t.Fatal("real service failed to reach running; cannot attribute rejection to invalid path")
}

func TestRealSwarmTaskReplacementInvalidatesFrozenSource(t *testing.T) {
	f := realFixture(t)
	id := f.service("replacement", "volume", "/data", "replicated", 1, nil)
	defer f.removeService(id)
	initial := f.targets(1)[0]
	var service struct {
		Version struct{ Index uint64 }
		Spec    map[string]any
	}
	f.mustAPI("GET", "/services/"+id, nil, &service)
	template := service.Spec["TaskTemplate"].(map[string]any)
	template["ForceUpdate"] = uint64(1)
	f.mustAPI("POST", fmt.Sprintf("/services/%s/update?version=%d", id, service.Version.Index), service.Spec, nil)
	for i := 0; i < 150; i++ {
		all, e := f.discover()
		if e == nil && len(all) == 1 && all[0].Source.ContainerID != initial.Source.ContainerID {
			if all[0].ID != initial.ID {
				t.Fatal("task ID leaked into logical source identity")
			}
			status, e := f.c.CheckSource(f.ctx, initial.Source)
			if e == nil && status == docker.SourceRunning {
				t.Fatal("frozen replaced source accepted as running")
			}
			if _, e = f.c.PrepareFileVolume(f.ctx, initial.Source, "/data"); e == nil {
				t.Fatal("stale frozen source silently rebound to new task")
			}
			t.Logf("real task replacement old=%s new=%s logical=%s; frozen source refused", initial.Source.ContainerID, all[0].Source.ContainerID, initial.ID)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("service force update did not produce new running task")
}

func TestRealOffNodeRunningTaskRefused(t *testing.T) {
	f := realFixture(t)
	worker := os.Getenv("BAKABEL_B3_WORKER_NODE")
	if worker == "" {
		t.Skip("run.py --worker required for a second actual isolated daemon")
	}
	id := f.service("offnode-running", "postgres", "", "replicated", 1, []string{"node.id==" + worker})
	defer f.removeService(id)
	for i := 0; i < 150; i++ {
		var tasks []struct {
			ServiceID, NodeID string
			Status            struct {
				State           string
				ContainerStatus struct{ ContainerID string }
			}
		}
		f.mustAPI("GET", "/tasks", nil, &tasks)
		for _, task := range tasks {
			if task.ServiceID == id && task.Status.State == "running" && task.NodeID == worker {
				if _, e := f.c.InspectContainer(f.ctx, task.Status.ContainerStatus.ContainerID); e == nil {
					t.Fatal("remote task unexpectedly local")
				}
				if _, e := f.discover(); !errors.Is(e, docker.ErrUnsupportedSource) {
					t.Fatalf("actual off-node running target not refused: %v", e)
				}
				t.Logf("real remote running task node=%s container=%s refused unsupported placement", worker, task.Status.ContainerStatus.ContainerID)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("real remote service never reached running; not evidence of off-node placement")
}

func TestS3CredentialAndMissingRepositoryFailures(t *testing.T) {
	f := realFixture(t)
	r := repository()
	_, e := r.Snapshots(f.ctx)
	if e != nil {
		t.Fatalf("operator-initialized S3 fixture unavailable: %v", e)
	}
	for _, tc := range []struct{ name, key, value string }{
		{"wrong-provider-auth", "AWS_SHARED_CREDENTIALS_FILE", "/credentials/wrong-aws"},
		{"wrong-restic-key", "RESTIC_PASSWORD_FILE", "/credentials/wrong-password"},
		{"missing-repository", "RESTIC_REPOSITORY", "s3:http://127.0.0.1:9000/bakabel-fixture/missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			bad.Env = append([]string{}, r.Env...)
			for i, v := range bad.Env {
				if strings.HasPrefix(v, tc.key+"=") {
					bad.Env[i] = tc.key + "=" + tc.value
				}
			}
			ctx, cancel := context.WithTimeout(f.ctx, 4*time.Second)
			defer cancel()
			if _, e := bad.Snapshots(ctx); e == nil {
				t.Fatal("bad repository access succeeded")
			}
			if tc.name == "wrong-provider-auth" {
				// Restic retries InvalidAccessKeyId rather than classifying it
				// permanent. Prove the provider replied, not just a deadline.
				diagCtx, done := context.WithTimeout(f.ctx, 2*time.Second)
				defer done()
				cmd := exec.CommandContext(diagCtx, bad.Binary, "--no-cache", "snapshots", "--json")
				cmd.Env = bad.Env
				out, _ := cmd.CombinedOutput()
				if !strings.Contains(string(out), "The Access Key Id you provided does not exist") {
					t.Fatalf("did not observe real authentication rejection: %s", out)
				}
				t.Log("provider InvalidAccessKeyId observed; Restic retry loop cancelled by bounded fixture deadline")
			} else if ctx.Err() != nil {
				t.Fatal("failure was only timeout, not password/missing-repository rejection")
			}
			t.Log("actual S3 access refused")
		})
	}
	// An explicit read of the missing prefix still fails: no implicit init occurred.
	r.Env = append([]string{}, r.Env...)
	for i, v := range r.Env {
		if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
			r.Env[i] = "RESTIC_REPOSITORY=s3:http://127.0.0.1:9000/bakabel-fixture/missing"
		}
	}
	if _, e := r.Snapshots(f.ctx); e == nil {
		t.Fatal("missing repository initialized implicitly")
	}
}

const dataSQL = `SELECT count(*)||':'||sum(id)||':'||md5(string_agg(payload,'' ORDER BY id)) FROM app.payload`
const objectSQL = `SELECT json_agg(x ORDER BY kind,name) FROM (
 SELECT 'relation' AS kind,n.nspname||'.'||c.relname AS name,pg_get_userbyid(c.relowner) AS owner,
 coalesce((SELECT json_agg(json_build_object('grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.privilege_type,pg_get_userbyid(a.grantee),a.is_grantable) FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a),'[]'::json) AS acl
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='app'
 UNION ALL SELECT 'schema',n.nspname,pg_get_userbyid(n.nspowner),coalesce((SELECT json_agg(json_build_object('grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.privilege_type,pg_get_userbyid(a.grantee),a.is_grantable) FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a),'[]'::json) FROM pg_namespace n WHERE n.nspname='app') x`

func TestSwarmS3StreamingPostgresIndependentRestore(t *testing.T) {
	f := realFixture(t)
	id := f.service("pgbackup", "postgres", "", "replicated", 1, nil)
	targets := f.targets(1)
	target := targets[0]
	src := target.Source
	f.ready(src)
	f.sql(src, "postgres", `CREATE ROLE dbowner; CREATE ROLE reader; ALTER DATABASE fixture OWNER TO dbowner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; GRANT CONNECT ON DATABASE fixture TO reader WITH GRANT OPTION;`)
	f.sql(src, "fixture", `CREATE SCHEMA app AUTHORIZATION dbowner; CREATE TABLE app.payload(id integer PRIMARY KEY,payload text); INSERT INTO app.payload SELECT g,repeat(md5(g::text),20) FROM generate_series(1,20000) g; ALTER TABLE app.payload OWNER TO dbowner; GRANT USAGE ON SCHEMA app TO reader; GRANT SELECT ON app.payload TO reader; CREATE TABLE app.live(id integer PRIMARY KEY,n integer);INSERT INTO app.live VALUES(1,0);`)
	expected := f.sql(src, "fixture", dataSQL)
	objects := f.sql(src, "fixture", objectSQL)
	before, e := f.c.InspectContainer(f.ctx, src.ContainerID)
	if e != nil {
		t.Fatal(e)
	}
	// Independent writer remains online while pg_dump runs (different table).
	liveID, e := f.c.CreateExec(f.ctx, src.ContainerID, docker.ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "--dbname", "host=/var/run/postgresql user=postgres dbname=fixture", "--command", `DO $$ BEGIN FOR i IN 1..100 LOOP UPDATE app.live SET n=n+1; PERFORM pg_sleep(0.05); END LOOP; END $$;`}})
	if e != nil {
		t.Fatal(e)
	}
	writerDone := make(chan error, 1)
	go func() {
		e := f.c.StartExec(f.ctx, liveID, io.Discard, io.Discard)
		code, w := f.c.WaitExec(f.ctx, liveID)
		if code != 0 {
			w = errors.Join(w, fmt.Errorf("writer exit %d", code))
		}
		writerDone <- errors.Join(e, w)
	}()
	p, e := f.c.PreparePostgresDatabase(f.ctx, src, target.Database)
	if e != nil {
		t.Fatal(e)
	}
	pg := p.Metadata
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: target.ID, Paths: []string{"/database.dump"}, Postgres: &backup.PostgresMetadata{Database: p.Database, ClusterID: pg.ClusterID, DatabaseOID: pg.DatabaseOID, ServerVersion: pg.ServerVersion, ClientVersion: pg.ClientVersion, Format: "custom", Owner: pg.Owner, ACL: []backup.Grant{}}}
	for _, g := range pg.ACL {
		m.Postgres.ACL = append(m.Postgres.ACL, backup.Grant{Grantee: g.Grantee, Grantor: g.Grantor, Privilege: g.Privilege, Grantable: g.Grantable})
	}
	missing := repository()
	missing.Env = append([]string{}, missing.Env...)
	for i, v := range missing.Env {
		if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
			missing.Env[i] = "RESTIC_REPOSITORY=s3:http://127.0.0.1:9000/bakabel-fixture/missing"
		}
	}
	failed := missing.Backup(f.ctx, m, "b3_missing_repo_probe", "b3fixture", nil)
	if failed.Err == nil || failed.SnapshotID != "" {
		t.Fatal("missing repository backup did not fail before upload", failed)
	}
	if _, e := missing.Snapshots(f.ctx); e == nil {
		t.Fatal("backup silently initialized missing S3 repository")
	}
	cp := filepath.Join(artifacts, "pg-export.json")
	if e := writeJSON(cp, map[string]string{"phase": "creating", "container": src.ContainerID}); e != nil {
		t.Fatal(e)
	}
	d, e := f.c.CreateDump(f.ctx, p, "b3_dump_0123456789abcdef", func(d docker.Dump) error { return writeJSON(cp, d) })
	if e != nil {
		t.Fatal(e)
	}
	r := repository()
	r.Env = append(r.Env, "BAKABEL_B3_DUMP_FILE="+cp)
	r.VerifySource = func(ctx context.Context) error {
		code, e := f.c.WaitExec(ctx, d.ExecID)
		if e != nil || code != 0 {
			return errors.New("dump terminal not successful")
		}
		return nil
	}
	result := r.Backup(f.ctx, m, "b3_pg_backup_0123456789", "b3fixture", []string{"--stdin-from-command", "--stdin-filename", "database.dump", "--", binary})
	if result.Err != nil || result.Status != "complete" {
		t.Fatal(result)
	}
	if e := <-writerDone; e != nil {
		t.Fatal(e)
	}
	if f.sql(src, "fixture", `SELECT n FROM app.live WHERE id=1`) != "100" {
		t.Fatal("online writer did not finish")
	}
	after, e := f.c.InspectContainer(f.ctx, src.ContainerID)
	if e != nil || after.State.StartedAt != before.State.StartedAt {
		t.Fatal("source incarnation changed", e)
	}
	var restart struct{ RestartCount int }
	f.mustAPI("GET", "/containers/"+src.ContainerID+"/json", nil, &restart)
	if restart.RestartCount != 0 {
		t.Fatal("source restarted")
	}
	affinity := f.run(src, "sh", "-c", `while IFS= read -r line; do case "$line" in Cpus_allowed_list*) printf '%s\n' "$line";; esac; done < /proc/1/status`)
	if !strings.Contains(affinity, "0-1") {
		t.Fatal("source CPU affinity escaped", affinity)
	}
	t.Logf("online writer=100 source unchanged restart_count=%d %s", restart.RestartCount, affinity)
	r = repository()
	snaps, e := r.Snapshots(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	var snap backup.Snapshot
	for _, s := range snaps {
		if s.ID == result.SnapshotID {
			snap = s
		}
	}
	if _, e = snap.Restorable(); e != nil {
		t.Fatal("exact complete snapshot readback", e)
	}
	if e = writeJSON(filepath.Join(artifacts, "pg.snapshot.json"), snap); e != nil {
		t.Fatal(e)
	}
	f.removeService(id)
	for i := 0; i < 100; i++ {
		v, e := f.c.InspectContainer(f.ctx, src.ContainerID)
		if e != nil || !v.State.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Explicitly remove exact old task container; no current source/state dependency.
	var old any
	if f.api("GET", "/containers/"+src.ContainerID+"/json", nil, &old) == nil {
		f.mustAPI("DELETE", "/containers/"+src.ContainerID+"?force=true&v=true", nil, nil)
	}
	if _, e = f.c.InspectContainer(f.ctx, src.ContainerID); e == nil {
		t.Fatal("source still present before restore")
	}
	if e = os.Remove(cp); e != nil {
		t.Fatal(e)
	}
	dst := f.container("b3-independent-pg", map[string]any{"Image": image, "Entrypoint": []string{binary}, "Cmd": []string{"fixture-exec", "/usr/local/bin/docker-entrypoint.sh", "postgres"}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_USER=postgres", "POSTGRES_DB=postgres"}, "HostConfig": map[string]any{"NetworkMode": "none", "Mounts": []map[string]any{bind("/fixture/bin", "/fixture/bin", true)}, "RestartPolicy": map[string]string{"Name": "no"}}})
	f.ready(dst)
	f.sql(dst, "postgres", `DO $$ BEGIN FOR i IN 1..20 LOOP EXECUTE 'CREATE ROLE extra_'||i;END LOOP;END $$;CREATE ROLE dbowner;CREATE ROLE reader;`)
	f.sql(dst, "postgres", `CREATE DATABASE restored TEMPLATE template0`)
	called := false
	opt := restore.RestoreOptions{PersistExec: func(d docker.RestoreExec) error {
		called = true
		return writeJSON(filepath.Join(artifacts, "pg-restore-checkpoint.json"), d)
	}}
	if _, e := restore.RestorePostgres(f.ctx, r, snap, f.c, dst, "restored", "postgres", opt); e == nil || called {
		t.Fatal("wrong database owner/ACL was accepted or wrote")
	}
	f.sql(dst, "postgres", `ALTER DATABASE restored OWNER TO dbowner;REVOKE CONNECT ON DATABASE restored FROM PUBLIC;GRANT CONNECT ON DATABASE restored TO reader WITH GRANT OPTION;`)
	restored, e := restore.RestorePostgres(f.ctx, r, snap, f.c, dst, "restored", "postgres", opt)
	if e != nil || restored.Status != "restored" {
		t.Fatalf("restore %+v %v", restored, e)
	}
	if got := f.sql(dst, "restored", dataSQL); got != expected {
		t.Fatalf("data got %s want %s", got, expected)
	}
	if got := f.sql(dst, "restored", objectSQL); got != objects {
		t.Fatalf("object owners/ACL mismatch\n%s\n%s", got, objects)
	}
	post, e := f.c.PrepareRestorePostgres(f.ctx, dst, "restored", "postgres")
	if e != nil || post.Metadata.ClusterID == pg.ClusterID || post.Metadata.Owner != pg.Owner || !reflect.DeepEqual(post.Metadata.ACL, pg.ACL) {
		t.Fatal("independent database identity/policy mismatch", post.Metadata, e)
	}
	t.Logf("exact complete S3 snapshot=%s restored source-gone independent cluster; data=%s objects/database owners+ACL match", snap.ID, expected)
}

func TestSwarmS3FilesCompleteUnknownPartialRestore(t *testing.T) {
	f := realFixture(t)
	sid := f.service("filesbackup", "volume", "/data", "replicated", 1, nil)
	targets := f.targets(1)
	target := targets[0]
	f.run(target.Source, "sh", "-c", `mkdir -p /data/sub;dd if=/dev/zero of=/data/sub/payload bs=1048576 count=4 2>/dev/null;printf 'swarm-s3-roundtrip\n' >> /data/sub/payload;chmod 0640 /data/sub/payload;chown 1234:2345 /data/sub/payload;printf 'readable\n' >/data/visible;chmod 0644 /data/visible`)
	v, e := f.c.PrepareFileVolume(f.ctx, target.Source, "/data")
	if e != nil {
		t.Fatal(e)
	}
	snap := f.fileWorker(fileJob{Action: "backup", Source: target.ID, Run: "files-complete", Volume: v}, true, "")
	unknown := f.fileWorker(fileJob{Action: "unknown", Source: target.ID, Run: "files-unknown", Volume: v}, true, "")
	if _, e := unknown.Restorable(); e == nil {
		t.Fatal("unknown accepted")
	}
	f.run(target.Source, "chmod", "000", "/data/sub/payload")
	partial := f.fileWorker(fileJob{Action: "partial", Source: target.ID, Run: "files-partial", Volume: v}, true, "1234:2345")
	if _, e := partial.Restorable(); e == nil {
		t.Fatal("partial accepted")
	}
	t.Logf("S3 complete=%s unknown=%s partial=%s; repository-restorable gate denies latter two", snap.ID, unknown.ID, partial.ID)
	for _, incomplete := range []backup.Snapshot{unknown, partial} {
		opened, err := files.OpenRestore(incomplete, "/fixture/destination", []string{"/credentials"})
		if err == nil {
			opened.Close()
			t.Fatal("incomplete S3 snapshot passed real file restore preflight")
		}
	}
	entries, err := os.ReadDir("/fixture/destination")
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected restore changed destination", err)
	}
	f.removeService(sid)
	// Source stopped/removed and an independent empty destination is explicit.
	for i := 0; i < 100; i++ {
		v, e := f.c.InspectContainer(f.ctx, target.Source.ContainerID)
		if e != nil || !v.State.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var old any
	if f.api("GET", "/containers/"+target.Source.ContainerID+"/json", nil, &old) == nil {
		f.mustAPI("DELETE", "/containers/"+target.Source.ContainerID+"?force=true&v=true", nil, nil)
	}
	if _, e = f.c.InspectContainer(f.ctx, target.Source.ContainerID); e == nil {
		t.Fatal("source still exists")
	}
	f.fileWorker(fileJob{Action: "restore", Run: "files-restore", Snapshot: snap, Destination: "/restore"}, false, "")
	b, e := os.ReadFile("/fixture/destination/sub/payload")
	if e != nil || len(b) != 4*1048576+len("swarm-s3-roundtrip\n") || !bytes.HasSuffix(b, []byte("swarm-s3-roundtrip\n")) {
		t.Fatal("payload bytes mismatch", len(b), e)
	}
	st, e := os.Stat("/fixture/destination/sub/payload")
	if e != nil || st.Mode().Perm() != 0640 {
		t.Fatal("mode mismatch", st, e)
	}
	own := st.Sys().(*syscall.Stat_t)
	if own.Uid != 1234 || own.Gid != 2345 {
		t.Fatal("ownership mismatch", own.Uid, own.Gid)
	}
	t.Logf("S3 independent files restore bytes=%d mode=%o uid=%d gid=%d", len(b), st.Mode().Perm(), own.Uid, own.Gid)
}

// Keep exec import tied to the real Restic binary's version diagnostics.
func TestPinnedResticBaseline(t *testing.T) {
	if os.Getenv("BAKABEL_B3_OPT_IN") != "isolated" {
		t.Skip("fixture required")
	}
	out, e := exec.Command("/fixture/bin/restic", "version").CombinedOutput()
	if e != nil || !strings.Contains(string(out), "restic 0.18.1") {
		t.Fatal(string(out), e)
	}
	t.Log(strings.TrimSpace(string(out)))
}
