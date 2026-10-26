package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

type fixture struct {
	t          *testing.T
	ctx        context.Context
	socket, id string
	c          *docker.Client
	http       *http.Client
	p          docker.Postgres
	bin        string
}

func token(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(b[:])
}
func (f *fixture) api(method, path string, body any, out any) int {
	f.t.Helper()
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r, e := http.NewRequestWithContext(f.ctx, method, "http://docker/v1.55"+path, &b)
	if e != nil {
		f.t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	response, e := f.http.Do(r)
	if e != nil {
		f.t.Fatal(e)
	}
	defer response.Body.Close()
	if out != nil && response.StatusCode < 300 {
		if e = json.NewDecoder(response.Body).Decode(out); e != nil {
			f.t.Fatal(e)
		}
	}
	if response.StatusCode >= 300 && response.StatusCode != 404 {
		f.t.Fatalf("fixture API %s %s: %d", method, path, response.StatusCode)
	}
	return response.StatusCode
}
func (f *fixture) control(argv ...string) string {
	f.t.Helper()
	id, e := f.c.CreateExec(f.ctx, f.id, docker.ExecConfig{User: "0", Cmd: argv})
	if e != nil {
		f.t.Fatal(e)
	}
	var b bytes.Buffer
	if e = f.c.StartExec(f.ctx, id, &b, io.Discard); e != nil {
		f.t.Fatal(e)
	}
	code, e := f.c.WaitExec(f.ctx, id)
	if e != nil || code != 0 {
		f.t.Fatalf("fixture control exit=%d err=%v", code, e)
	}
	return b.String()
}
func (f *fixture) sql(q string) string {
	return f.control("psql", "-XAt", "--no-password", "-U", "postgres", "-d", "fixture", "-c", q)
}
func realFixture(t *testing.T) *fixture {
	t.Helper()
	socket := os.Getenv("BAKABEL_DOCKER_SOCKET")
	if socket == "" || os.Getenv("RESTIC_TEST_BINARY") == "" {
		t.Skip("explicit disposable Docker/Restic opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	c, e := docker.NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{t: t, ctx: ctx, socket: socket, c: c}
	f.http = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	name := "bakabel-b1-integrated-" + token(t)
	var created struct {
		ID string `json:"Id"`
	}
	f.api("POST", "/containers/create?name="+name, map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"sh", "-c", "while [ ! -e /tmp/bakabel-init-ready ]; do sleep 0.1; done; exec docker-entrypoint.sh postgres"}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_DB=fixture", "POSTGRES_USER=postgres"}, "HostConfig": map[string]any{"NanoCpus": 2000000000, "CpusetCpus": "0,1", "NetworkMode": "none"}}, &created)
	f.id = created.ID
	if f.id == "" {
		t.Fatal("missing fixture ID")
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f.ctx = clean
		f.api("DELETE", "/containers/"+f.id+"?force=true&v=true", nil, nil)
		if code := f.api("GET", "/containers/"+f.id+"/json", nil, nil); code != 404 {
			t.Error("fixture cleanup readback", code)
		} else {
			t.Log("fixture cleanup exact ID verified 404", f.id)
		}
	})
	f.api("POST", "/containers/"+f.id+"/start", nil, nil)
	source, e := c.CaptureSource(ctx, f.id)
	if e != nil {
		t.Fatal(e)
	}
	v, e := c.InspectContainer(ctx, f.id)
	if e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("taskset", "-pc", "0,1", strconv.Itoa(v.State.Pid)).CombinedOutput(); e != nil {
		t.Fatalf("fixture affinity --pid host required %s %v", out, e)
	}
	f.control("sh", "-c", ": > /tmp/bakabel-init-ready")
	for {
		id, e := c.CreateExec(ctx, f.id, docker.ExecConfig{User: "0", Cmd: []string{"pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "fixture"}})
		if e == nil {
			e = c.StartExec(ctx, id, io.Discard, io.Discard)
			code, we := c.WaitExec(ctx, id)
			if e == nil && we == nil && code == 0 {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("readiness timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
	f.p, e = c.PreparePostgres(ctx, source)
	if e != nil {
		t.Fatal("prepare", e)
	}
	f.sql("CREATE TABLE payload AS SELECT g,md5(g::text) AS data FROM generate_series(1,20000)g")
	f.bin = filepath.Join(t.TempDir(), "bakabel")
	build := exec.CommandContext(ctx, "go", "build", "-o", f.bin, "../../cmd/bakabel")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("compile application: %s %v", out, e)
	}
	raw, e := os.ReadFile(f.bin)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("compiled application sha256=%x fixture=%s source=%s", sha256.Sum256(raw), name, f.id)
	return f
}
func repoFixture(t *testing.T, ctx context.Context) backup.Repository {
	t.Helper()
	dir := t.TempDir()
	pass := filepath.Join(dir, "password")
	if e := os.WriteFile(pass, []byte("disposable-test-only"), 0600); e != nil {
		t.Fatal(e)
	}
	env := append(os.Environ(), "RESTIC_REPOSITORY="+filepath.Join(dir, "repo"), "RESTIC_PASSWORD_FILE="+pass)
	binary := os.Getenv("RESTIC_TEST_BINARY")
	cmd := exec.CommandContext(ctx, binary, "init")
	cmd.Env = env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("init fixture %s %v", out, e)
	}
	return backup.Repository{Binary: binary, Env: env}
}
func metadata(p docker.Postgres) backup.Metadata {
	m := p.Metadata
	acl := make([]backup.Grant, 0, len(m.ACL))
	for _, g := range m.ACL {
		acl = append(acl, backup.Grant{Grantor: g.Grantor, Grantee: g.Grantee, Privilege: g.Privilege, Grantable: g.Grantable})
	}
	return backup.Metadata{Version: 1, Kind: "postgres", Source: "fixture/postgres", Paths: []string{"/postgres.dump"}, Postgres: &backup.PostgresMetadata{Database: m.Database, ClusterID: m.ClusterID, DatabaseOID: m.DatabaseOID, ServerVersion: m.ServerVersion, ClientVersion: m.ClientVersion, Format: m.Format, Owner: m.Owner, ACL: acl}}
}
func newOwner(t *testing.T) *state.Owner {
	t.Helper()
	o, e := state.Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func TestRealApplicationResticPipeline(t *testing.T) {
	f := realFixture(t)
	r := repoFixture(t, f.ctx)
	r, unknownFile := observeUnknown(t, r)
	o := newOwner(t)
	run := token(t)
	d, e := Prepare(f.ctx, o, f.c, f.p, run, "helper-"+run)
	if e != nil {
		t.Fatal(e)
	}
	durable, e := o.Load()
	if e != nil || durable.ExecID != d.ExecID || durable.Phase != state.PhaseExecCreated {
		t.Fatalf("exec not durable before start %+v %v", durable, e)
	}
	status, e := f.c.PollExec(f.ctx, d.ExecID)
	if e != nil || status.Running {
		t.Fatal("dump prematurely started", status, e)
	}
	tap, digest := digestTap(run)
	proxy := newRawProxy(t, f.socket, false, tap)
	args, e := Authorize(o, proxy.socket, d, 60*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	result := r.Backup(f.ctx, metadata(f.p), run, "b1-fixture", append([]string{"--stdin-from-command", "--stdin-filename", "postgres.dump", "--", f.bin}, args...))
	if result.Err != nil || result.Status != "complete" || len(result.SnapshotID) != 64 {
		t.Fatalf("pipeline %+v", result)
	}
	assertUnknownTransition(t, unknownFile, result.SnapshotID)
	snapshots, e := r.Snapshots(f.ctx)
	if e != nil || len(snapshots) != 1 || snapshots[0].ID != result.SnapshotID {
		t.Fatal("final ID readback", snapshots, e)
	}
	var restored bytes.Buffer
	if e = r.Dump(f.ctx, result.SnapshotID, "/postgres.dump", &restored); e != nil {
		t.Fatal(e)
	}
	if !bytes.HasPrefix(restored.Bytes(), []byte("PGDMP")) {
		t.Fatal("not custom dump")
	}
	select {
	case <-digest.done:
	case <-time.After(5 * time.Second):
		t.Fatal("source digest not terminal")
	}
	sum := sha256.Sum256(restored.Bytes())
	if digest.err != nil || digest.n != int64(restored.Len()) || !bytes.Equal(digest.Sum(nil), sum[:]) {
		t.Fatalf("source/restored byte mismatch sourceBytes=%d restoredBytes=%d err=%v", digest.n, restored.Len(), digest.err)
	}
	t.Logf("source stdout and exact snapshot dump byte-for-byte digest match bytes=%d sha256=%x", digest.n, sum)
	proof, e := legacyRecover(f.ctx, o, f.c, func(context.Context, string) (bool, error) { return true, nil }, state.OutcomeSuccess)
	if e != nil || proof.ExecExitCode == nil || *proof.ExecExitCode != 0 || !proof.NoProcesses || !proof.NoSessions {
		t.Fatal("terminal readback", proof, e)
	}
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("ownership not released", e)
	}
	t.Logf("complete finalID=%s restored_bytes=%d restored_sha256=%x source_exit=%d processes=0 sessions=0", result.SnapshotID, restored.Len(), sha256.Sum256(restored.Bytes()), *proof.ExecExitCode)
	// Real producer failure through the SAME application and repository API: no snapshot.
	bad := f.p
	bad.Database = "nonexistent_fixture_database"
	badRun := token(t)
	d, e = Prepare(f.ctx, o, f.c, bad, badRun, "helper-"+badRun)
	if e != nil {
		t.Fatal(e)
	}
	args, e = Authorize(o, f.socket, d, 60*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	failed := r.Backup(f.ctx, metadata(f.p), badRun, "b1-fixture", append([]string{"--stdin-from-command", "--stdin-filename", "postgres.dump", "--", f.bin}, args...))
	if failed.Err == nil || failed.SnapshotID != "" || failed.Status == "complete" {
		t.Fatalf("producer failure %+v", failed)
	}
	after, e := r.Snapshots(f.ctx)
	if e != nil || len(after) != 1 || after[0].ID != result.SnapshotID {
		t.Fatal("failed producer created snapshot", after, e)
	}
	x, e := f.c.PollExec(f.ctx, d.ExecID)
	if e != nil || x.ExitCode == nil || *x.ExitCode == 0 {
		t.Fatal("failure source exit", x, e)
	}
	t.Logf("producer failure source_exit=%d new_snapshots=0 result=%s", *x.ExitCode, failed.Status)
	// Even an explicit caller success request may not turn a failed export into
	// a durable successful result. Retain ownership for reviewed recovery.
	if _, e = legacyRecover(f.ctx, o, f.c, func(context.Context, string) (bool, error) { return true, nil }, state.OutcomeSuccess); !errors.Is(e, docker.ErrQuarantine) {
		t.Fatalf("nonzero source accepted as success: %v", e)
	}
	// The legacy recovery adapter rediscovers the configured database rather
	// than this test's deliberately invalid override. Exact argv validation must
	// retain quarantine, not claim that those two different exports match.
	if _, e = legacyRecover(f.ctx, o, f.c, func(context.Context, string) (bool, error) { return true, nil }, state.OutcomeFailed); !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal("mismatched legacy export released", e)
	}
	// Even the correct argv cannot use this nonexistent database for SQL
	// session proof. Retain ownership rather than bypassing that prerequisite.
	if _, e = f.c.CancelDump(f.ctx, d); !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal("unavailable failed-database proof released ownership", e)
	}
	if got := f.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='" + badRun + "'"); got != "0\n" {
		t.Fatal("failed producer session remained", got)
	}
}
