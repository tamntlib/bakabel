package restore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

// No state file: Restic invokes this process only while creating the fixture.
func TestPostgresDumpFixtureProcess(t *testing.T) {
	if os.Getenv("BAKABEL_B2_DUMP") == "" {
		return
	}
	var d docker.Dump
	if json.Unmarshal([]byte(os.Getenv("BAKABEL_B2_DUMP")), &d) != nil {
		os.Exit(2)
	}
	c, e := docker.NewClient(os.Getenv("BAKABEL_B2_SOCKET"))
	if e != nil {
		os.Exit(2)
	}
	code, e := c.StreamDump(context.Background(), d, os.Stdout)
	if e != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

type pgFixture struct {
	t      *testing.T
	ctx    context.Context
	c      *docker.Client
	h      *http.Client
	socket string
}

func (f pgFixture) api(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(f.ctx, method, "http://docker/v1.55"+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	r, e := f.h.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return fmt.Errorf("docker status %d", r.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(r.Body).Decode(out)
	}
	return nil
}
func (f pgFixture) run(s docker.Source, cmd ...string) string {
	f.t.Helper()
	id, e := f.c.CreateExec(f.ctx, s.ContainerID, docker.ExecConfig{User: "0", Cmd: cmd})
	if e != nil {
		f.t.Fatal(e)
	}
	var out, errout bytes.Buffer
	e = f.c.StartExec(f.ctx, id, &out, &errout)
	code, w := f.c.WaitExec(f.ctx, id)
	if e != nil || w != nil || code != 0 {
		f.t.Fatalf("fixture command code=%d stream=%v wait=%v stderr=%s", code, e, w, errout.String())
	}
	return strings.TrimSpace(out.String())
}
func qid(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func testConn(db string) string {
	return "host='/var/run/postgresql' port='5432' user='postgres' dbname='" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(db) + "'"
}
func (f pgFixture) sql(s docker.Source, db, q string) string {
	return f.run(s, "/usr/local/bin/psql", "-XAt", "-v", "ON_ERROR_STOP=1", "--dbname", testConn(db), "--command", q)
}
func (f pgFixture) container(suffix string) docker.Source {
	f.t.Helper()
	name := fmt.Sprintf("bakabel-b2-pg-%s-%d", suffix, time.Now().UnixNano())
	var out struct {
		ID string `json:"Id"`
	}
	cfg := map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"sh", "-c", "while [ ! -e /tmp/bakabel-b2-ready ]; do sleep 0.1; done; exec docker-entrypoint.sh postgres"}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_DB=postgres", "POSTGRES_USER=postgres"}, "HostConfig": map[string]any{"NetworkMode": "none", "CpusetCpus": "0,1", "NanoCpus": 2000000000}}
	if e := f.api("POST", "/containers/create?name="+name, cfg, &out); e != nil {
		f.t.Fatal(e)
	}
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		clean := f
		clean.ctx = ctx
		_ = clean.api("DELETE", "/containers/"+out.ID+"?force=true&v=true", nil, nil)
		if _, e := f.c.InspectContainer(ctx, out.ID); e == nil {
			f.t.Error("fixture cleanup not verified")
		}
	})
	if e := f.api("POST", "/containers/"+out.ID+"/start", nil, nil); e != nil {
		f.t.Fatal(e)
	}
	s, e := f.c.CaptureSource(f.ctx, out.ID)
	if e != nil {
		f.t.Fatal(e)
	}
	v, e := f.c.InspectContainer(f.ctx, s.ContainerID)
	if e != nil {
		f.t.Fatal(e)
	}
	if out, e := exec.Command("taskset", "-pc", "0,1", fmt.Sprint(v.State.Pid)).CombinedOutput(); e != nil {
		f.t.Fatalf("host affinity %s %v (runner needs --pid host)", out, e)
	}
	f.run(s, "sh", "-c", ": > /tmp/bakabel-b2-ready")
	for i := 0; ; i++ {
		id, e := f.c.CreateExec(f.ctx, s.ContainerID, docker.ExecConfig{User: "0", Cmd: []string{"/usr/local/bin/pg_isready", "-h", "127.0.0.1", "-U", "postgres"}})
		if e == nil {
			e = f.c.StartExec(f.ctx, id, io.Discard, io.Discard)
			code, w := f.c.WaitExec(f.ctx, id)
			if e == nil && w == nil && code == 0 {
				break
			}
		}
		if i > 100 {
			f.t.Fatal("fixture readiness timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	affinity := f.run(s, "sh", "-c", `while IFS= read -r line; do case "$line" in Cpus_allowed_list*) printf '%s\n' "$line";; esac; done < /proc/1/status`)
	if !strings.Contains(affinity, "0-1") {
		f.t.Fatal("fixture escaped affinity", affinity)
	}
	f.t.Logf("fixture=%s container=%s %s", name, s.ContainerID, affinity)
	return s
}
func realPGFixture(t *testing.T) pgFixture {
	t.Helper()
	socket := os.Getenv("BAKABEL_B2_SOCKET")
	if socket == "" {
		t.Skip("explicit disposable Docker/Restic fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	c, e := docker.NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	h := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	return pgFixture{t, ctx, c, h, socket}
}

const objectContractSQL = `SELECT json_agg(x ORDER BY kind,name) FROM (
 SELECT 'relation' AS kind,n.nspname||'.'||c.relname AS name,pg_get_userbyid(c.relowner) AS owner,
 coalesce((SELECT json_agg(json_build_object('grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.privilege_type,pg_get_userbyid(a.grantee),a.is_grantable) FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a),'[]'::json) AS acl
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='app'
 UNION ALL SELECT 'schema',n.nspname,pg_get_userbyid(n.nspowner),coalesce((SELECT json_agg(json_build_object('grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.privilege_type,pg_get_userbyid(a.grantee),a.is_grantable) FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a),'[]'::json) FROM pg_namespace n WHERE n.nspname='app'
 UNION ALL SELECT 'function',n.nspname||'.'||p.proname,pg_get_userbyid(p.proowner),coalesce((SELECT json_agg(json_build_object('grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.privilege_type,pg_get_userbyid(a.grantee),a.is_grantable) FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a),'[]'::json) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app'
 ) x`
const dataContractSQL = `SELECT json_build_object('rows',count(*),'sum',sum(id),'hash',md5(string_agg(payload,'' ORDER BY id)),'answer',app.answer()) FROM app.payload`

func captureSnapshot(t *testing.T, f pgFixture, src docker.Source, db string) (backup.Repository, backup.Snapshot) {
	t.Helper()
	p, e := f.c.PrepareRestorePostgres(f.ctx, src, db, "postgres")
	if e != nil {
		t.Fatal(e)
	}
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: "lost-fixture", Paths: []string{"/database.dump"}, Postgres: &backup.PostgresMetadata{Database: db, ClusterID: p.Metadata.ClusterID, DatabaseOID: p.Metadata.DatabaseOID, ServerVersion: p.Metadata.ServerVersion, ClientVersion: p.Metadata.ClientVersion, Format: "custom", Owner: p.Metadata.Owner, ACL: []backup.Grant{}}}
	for _, g := range p.Metadata.ACL {
		m.Postgres.ACL = append(m.Postgres.ACL, backup.Grant{Grantor: g.Grantor, Grantee: g.Grantee, Privilege: g.Privilege, Grantable: g.Grantable})
	}
	export, e := f.c.PreparePostgres(f.ctx, src)
	if e != nil {
		t.Fatal(e)
	}
	export.Database = db
	d, e := f.c.CreateDump(f.ctx, export, "fixture_dump_0123456789abcdef", func(docker.Dump) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	bin, _ := os.Executable()
	raw, _ := json.Marshal(d)
	dir := t.TempDir()
	env := append(os.Environ(), "RESTIC_REPOSITORY="+filepath.Join(dir, "repository"), "RESTIC_PASSWORD=disposable-b2-fixture")
	repo := backup.Repository{Binary: os.Getenv("BAKABEL_B2_RESTIC"), Env: append(append([]string{}, env...), "BAKABEL_B2_DUMP="+string(raw))}
	cmd := exec.CommandContext(f.ctx, repo.Binary, "init")
	cmd.Env = repo.Env
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("restic init %s %v", out, e)
	}
	b := repo.Backup(f.ctx, m, "fixture_backup_0123456789", "fixture", []string{"--stdin-from-command", "--stdin-filename", "database.dump", "--", bin, "-test.run=^TestPostgresDumpFixtureProcess$"})
	if b.Err != nil || b.Status != "complete" {
		t.Fatal(b)
	}
	repo.Env = env
	snaps, e := repo.Snapshots(f.ctx)
	if e != nil || len(snaps) != 1 {
		t.Fatal(snaps, e)
	}
	return repo, snaps[0]
}

func TestPostgresIndependentActualRestore(t *testing.T) {
	f := realPGFixture(t)
	src := f.container("source")
	sourceDB := "source fixture"
	f.sql(src, "postgres", `CREATE ROLE "db owner"; CREATE ROLE reader; CREATE ROLE "object only"; CREATE ROLE delegator;`)
	f.sql(src, "postgres", "CREATE DATABASE "+qid(sourceDB)+" TEMPLATE template0 OWNER "+qid("db owner"))
	f.sql(src, "postgres", "REVOKE CONNECT ON DATABASE "+qid(sourceDB)+" FROM PUBLIC; GRANT CONNECT ON DATABASE "+qid(sourceDB)+" TO reader WITH GRANT OPTION; SET ROLE reader; GRANT CONNECT ON DATABASE "+qid(sourceDB)+" TO delegator; RESET ROLE;")
	f.sql(src, sourceDB, `CREATE SCHEMA app AUTHORIZATION "db owner"; CREATE TABLE app.payload(id serial PRIMARY KEY,payload text); INSERT INTO app.payload(payload) SELECT repeat(md5(g::text),20) FROM generate_series(1,20000) g; ALTER TABLE app.payload OWNER TO "object only"; CREATE VIEW app.half AS SELECT * FROM app.payload WHERE id%2=0; ALTER VIEW app.half OWNER TO "db owner"; CREATE FUNCTION app.answer() RETURNS integer LANGUAGE sql AS 'SELECT 42'; ALTER FUNCTION app.answer() OWNER TO "object only"; REVOKE ALL ON FUNCTION app.answer() FROM PUBLIC; GRANT EXECUTE ON FUNCTION app.answer() TO reader; GRANT USAGE ON SCHEMA app TO reader; GRANT SELECT ON TABLE app.payload TO reader WITH GRANT OPTION; SET ROLE reader; GRANT SELECT ON TABLE app.payload TO delegator; RESET ROLE;`)
	p, e := f.c.PrepareRestorePostgres(f.ctx, src, sourceDB, "postgres")
	if e != nil {
		t.Fatal(e)
	}
	// Backup metadata/export is collected from the actual source; fixture helper only.
	rolesSQL := `SELECT json_object_agg(rolname,oid::text) FROM pg_roles WHERE rolname IN ('db owner','reader','object only','delegator')`
	var sourceRoles map[string]string
	if e := json.Unmarshal([]byte(f.sql(src, sourceDB, rolesSQL)), &sourceRoles); e != nil {
		t.Fatal(e)
	}
	sourceOID := sourceRoles["object only"]
	objects := f.sql(src, sourceDB, objectContractSQL)
	data := f.sql(src, sourceDB, dataContractSQL)
	repo, snap := captureSnapshot(t, f, src, sourceDB)
	if e = f.api("DELETE", "/containers/"+src.ContainerID+"?force=true&v=true", nil, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = f.c.InspectContainer(f.ctx, src.ContainerID); e == nil {
		t.Fatal("source still present")
	}
	// The independent function receives only repository/snapshot and explicit target.
	dst := f.container("target")
	f.sql(dst, "postgres", `DO $$ BEGIN FOR i IN 1..40 LOOP EXECUTE 'CREATE ROLE unused_'||i; END LOOP; END $$; CREATE ROLE "db owner"; CREATE ROLE reader; CREATE ROLE "object only"; CREATE ROLE delegator;`)
	targetDB := `postgresql://x/y db=a '\` // literal URI, equals, space, quote, backslash
	f.sql(dst, "postgres", "CREATE DATABASE "+qid(targetDB)+" TEMPLATE template0")
	var targetRoles map[string]string
	if e := json.Unmarshal([]byte(f.sql(dst, "postgres", rolesSQL)), &targetRoles); e != nil {
		t.Fatal(e)
	}
	if len(sourceRoles) != 4 || len(targetRoles) != 4 {
		t.Fatal("missing fixture role identities")
	}
	for name, oid := range sourceRoles {
		if targetRoles[name] == "" || targetRoles[name] == oid {
			t.Fatal("roles accidentally share OIDs", name, oid)
		}
	}
	targetOID := targetRoles["object only"]
	called := false
	opt := RestoreOptions{PersistExec: func(d docker.RestoreExec) error {
		called = true
		if d.Target != dst || d.Database != targetDB || d.ExecID == "" {
			return fmt.Errorf("wrong checkpoint")
		}
		return nil
	}}
	reject := func(label string) {
		t.Helper()
		called = false
		r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, targetDB, "postgres", opt)
		if e == nil || r.Status == "restored" || called {
			t.Fatalf("%s accepted/wrote %+v %v checkpoint=%v", label, r, e, called)
		}
		if got := f.sql(dst, targetDB, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'`); got != "0" {
			t.Fatal("preflight wrote objects", got)
		}
		t.Log(label, e)
	}
	reject("wrong owner/ACL")
	f.sql(dst, "postgres", "ALTER DATABASE "+qid(targetDB)+" OWNER TO "+qid("db owner"))
	reject("matching owner only, wrong PUBLIC/grant option ACL")
	f.sql(dst, "postgres", "REVOKE CONNECT ON DATABASE "+qid(targetDB)+" FROM PUBLIC; GRANT CONNECT ON DATABASE "+qid(targetDB)+" TO reader")
	reject("PUBLIC correct but missing grant option/delegated grantor")
	f.sql(dst, "postgres", "GRANT CONNECT ON DATABASE "+qid(targetDB)+" TO reader WITH GRANT OPTION; SET ROLE reader; GRANT CONNECT ON DATABASE "+qid(targetDB)+" TO delegator; RESET ROLE")
	// The successful import runs in a brand-new OS process with no source/export
	// state. Only the repository handoff and explicit destination are supplied.
	checkpoint := filepath.Join(t.TempDir(), "target-active.json")
	job := restoreWorkerJob{repo, snap, dst, targetDB, checkpoint}
	jobJSON, _ := json.Marshal(job)
	bin, _ := os.Executable()
	child := exec.CommandContext(f.ctx, bin, "-test.run=^TestPostgresRestoreWorkerFixtureProcess$")
	child.Env = append(os.Environ(), "BAKABEL_B2_RESTORE_JOB="+string(jobJSON))
	out, e := child.CombinedOutput()
	if e != nil {
		t.Fatalf("independent child restore %s %v", out, e)
	}
	var r PostgresResult
	if e = json.Unmarshal(out, &r); e != nil || r.Status != "restored" {
		t.Fatalf("independent result %s %v", out, e)
	}
	cp, e := os.ReadFile(checkpoint)
	if e != nil {
		t.Fatal("durable target checkpoint missing", e)
	}
	var persisted docker.RestoreExec
	if json.Unmarshal(cp, &persisted) != nil || persisted != r.Exec {
		t.Fatal("checkpoint readback differs", string(cp), r.Exec)
	}
	if got := f.sql(dst, targetDB, objectContractSQL); got != objects {
		t.Fatalf("object owner/ACL contract differs\nsource=%s\ntarget=%s", objects, got)
	}
	if got := f.sql(dst, targetDB, dataContractSQL); got != data {
		t.Fatalf("data contract differs %s %s", data, got)
	}
	post, e := f.c.PrepareRestorePostgres(f.ctx, dst, targetDB, "postgres")
	if e != nil {
		t.Fatal(e)
	}
	if post.Metadata.Owner != p.Metadata.Owner || !reflect.DeepEqual(post.Metadata.ACL, p.Metadata.ACL) {
		t.Fatal("database owner/ACL differs", post.Metadata, p.Metadata)
	}
	if post.Metadata.ClusterID == p.Metadata.ClusterID {
		t.Fatal("clusters not independent")
	}
	proof, e := f.c.CancelRestoreExec(f.ctx, r.Exec)
	if e != nil || !proof.NoProcesses || !proof.NoSessions || proof.ExecNeverStarted || proof.ExecExitCode == nil || *proof.ExecExitCode != 0 {
		t.Fatal("terminal recovery proof", proof, e)
	}
	t.Logf("snapshot=%s source absent; independent cluster=%s; role OIDs %s != %s; %s; reader and pg_restore exit=0; owners/objectACL/databaseACL preserved", snap.ID, post.Metadata.ClusterID, sourceOID, targetOID, data)
}
