package restore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestPostgresActualFailureStatuses(t *testing.T) {
	f := realPGFixture(t)
	src := f.container("fail-source")
	f.sql(src, "postgres", `CREATE ROLE "object only"; CREATE TABLE public.payload AS SELECT g FROM generate_series(1,300) g; ALTER TABLE public.payload OWNER TO "object only"`)
	repo, snap := captureSnapshot(t, f, src, "postgres")
	if e := f.api("DELETE", "/containers/"+src.ContainerID+"?force=true&v=true", nil, nil); e != nil {
		t.Fatal(e)
	}
	dst := f.container("fail-target")
	opts := RestoreOptions{PersistExec: func(docker.RestoreExec) error { return nil }}
	create := func(db string) { t.Helper(); f.sql(dst, "postgres", "CREATE DATABASE "+qid(db)+" TEMPLATE template0") }
	t.Run("missing-object-role-retains-partial-database", func(t *testing.T) {
		create("missing role")
		r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, "missing role", "postgres", opts)
		if e == nil || r.Status == "restored" || r.ImportExitCode == nil || *r.ImportExitCode == 0 || !r.Terminal.NoProcesses || !r.Terminal.NoSessions {
			t.Fatalf("%+v %v", r, e)
		}
		if f.sql(dst, "missing role", `SELECT to_regclass('public.payload') IS NOT NULL`) != "t" {
			t.Fatal("partial target lost")
		}
		if f.sql(dst, "postgres", `SELECT count(*) FROM pg_roles WHERE rolname='object only'`) != "0" {
			t.Fatal("role was automatically created")
		}
		t.Logf("authentic pg_restore exit=%d; partial target retained: %v", *r.ImportExitCode, e)
	})
	f.sql(dst, "postgres", `CREATE ROLE "object only"`)
	t.Run("NULL-default-ACL-equals-explicit-default-ACL", func(t *testing.T) {
		db := "normalized default"
		create(db)
		if f.sql(dst, db, `SELECT datacl IS NULL FROM pg_database WHERE datname=current_database()`) != "t" {
			t.Fatal("fixture ACL not NULL")
		}
		f.sql(dst, "postgres", "GRANT CONNECT,TEMPORARY ON DATABASE "+qid(db)+" TO PUBLIC; GRANT CREATE,CONNECT,TEMPORARY ON DATABASE "+qid(db)+" TO postgres")
		if f.sql(dst, db, `SELECT datacl IS NOT NULL FROM pg_database WHERE datname=current_database()`) != "t" {
			t.Fatal("explicit default not materialized")
		}
		r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, db, "postgres", opts)
		if e != nil || r.Status != "restored" {
			t.Fatal(r, e)
		}
		if f.sql(dst, db, `SELECT count(*) FROM payload`) != "300" {
			t.Fatal("data missing")
		}
	})
	for i, db := range []string{"literal = spaced", `postgresql://remote/other`, `x' dbname='postgres' host='evil`, `slashes\and'quotes =x`} {
		t.Run(fmt.Sprintf("literal-%d", i), func(t *testing.T) {
			create(db)
			r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, db, "postgres", opts)
			if e != nil || r.Status != "restored" {
				t.Fatal(r, e)
			}
			if f.sql(dst, db, `SELECT current_database()`) != db || f.sql(dst, db, `SELECT count(*) FROM payload`) != "300" {
				t.Fatal("connection fields changed")
			}
		})
	}
	t.Run("reader-exit-17-after-complete-content-import-exit-0", func(t *testing.T) {
		db := "reader fails late"
		create(db)
		wrapper := filepath.Join(t.TempDir(), "reader")
		script := "#!/bin/sh\nif [ \"$2\" = dump ]; then\n  \"$BAKABEL_B2_RESTIC\" \"$@\" || exit $?\n  exit 17\nfi\nexec \"$BAKABEL_B2_RESTIC\" \"$@\"\n"
		if e := os.WriteFile(wrapper, []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		bad := repo
		bad.Binary = wrapper
		r, e := RestorePostgres(f.ctx, bad, snap, f.c, dst, db, "postgres", opts)
		if e == nil || r.Status == "restored" || r.ImportExitCode == nil || *r.ImportExitCode != 0 || !strings.Contains(e.Error(), "exit 17") {
			t.Fatalf("reader failure masked by importer: %+v %v", r, e)
		}
		if f.sql(dst, db, `SELECT count(*) FROM payload`) != "300" {
			t.Fatal("reader did not deliver complete content")
		}
		t.Logf("authentic reader exit=17 pg_restore exit=0: %v", e)
	})
	t.Run("truncated-reader-exit-0-import-nonzero", func(t *testing.T) {
		db := "truncated"
		create(db)
		wrapper := filepath.Join(t.TempDir(), "reader")
		script := "#!/bin/sh\nif [ \"$2\" = dump ]; then\n  \"$BAKABEL_B2_RESTIC\" \"$@\" | head -c 96\n  exit 0\nfi\nexec \"$BAKABEL_B2_RESTIC\" \"$@\"\n"
		if e := os.WriteFile(wrapper, []byte(script), 0700); e != nil {
			t.Fatal(e)
		}
		bad := repo
		bad.Binary = wrapper
		r, e := RestorePostgres(f.ctx, bad, snap, f.c, dst, db, "postgres", opts)
		if e == nil || r.Status == "restored" || r.ImportExitCode == nil || *r.ImportExitCode == 0 {
			t.Fatalf("truncated accepted %+v %v", r, e)
		}
		t.Logf("authentic truncating reader exit=0 importer=%d: %v", *r.ImportExitCode, e)
	})
	t.Run("post-import-database-ACL-readback", func(t *testing.T) {
		db := "post drift"
		create(db)
		f.sql(dst, "postgres", `CREATE ROLE unexpected`)
		drift := RestoreOptions{PersistExec: func(docker.RestoreExec) error {
			f.sql(dst, "postgres", "GRANT CONNECT ON DATABASE "+qid(db)+" TO unexpected")
			return nil
		}}
		r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, db, "postgres", drift)
		if e == nil || r.Status == "restored" || !strings.Contains(e.Error(), "post-import") || r.ImportExitCode == nil || *r.ImportExitCode != 0 {
			t.Fatalf("DB ACL drift not checked %+v %v", r, e)
		}
		if f.sql(dst, db, `SELECT count(*) FROM payload`) != "300" {
			t.Fatal("partial result auto-dropped")
		}
	})
	t.Run("cancel-after-checkpoint-before-start-is-proven-unstarted", func(t *testing.T) {
		db := "cancel before start"
		create(db)
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		r, e := RestorePostgres(ctx, repo, snap, f.c, dst, db, "postgres", RestoreOptions{PersistExec: func(docker.RestoreExec) error { cancel(); return nil }})
		if e == nil || r.Status == "restored" || !r.Terminal.ExecNeverStarted || !r.Terminal.NoProcesses || !r.Terminal.NoSessions || r.ImportExitCode != nil {
			t.Fatalf("known-unstarted import unnecessarily quarantined: %+v %v", r, e)
		}
		if f.sql(dst, db, `SELECT to_regclass('public.payload') IS NULL`) != "t" {
			t.Fatal("canceled import wrote objects")
		}
	})
	t.Run("checkpoint-error-never-starts-import", func(t *testing.T) {
		db := "checkpoint fail"
		create(db)
		r, e := RestorePostgres(f.ctx, repo, snap, f.c, dst, db, "postgres", RestoreOptions{PersistExec: func(docker.RestoreExec) error { return io.ErrClosedPipe }})
		if e == nil || r.Exec.ExecID == "" || !r.Terminal.ExecNeverStarted || !r.Terminal.NoProcesses || !r.Terminal.NoSessions {
			t.Fatal(r, e)
		}
		status, e := f.c.PollExec(f.ctx, r.Exec.ExecID)
		if e != nil || status.Running || status.Pid != 0 {
			t.Fatal("started before checkpoint", status, e)
		}
		if f.sql(dst, db, `SELECT to_regclass('public.payload') IS NULL`) != "t" {
			t.Fatal("import wrote despite checkpoint failure")
		}
		proof, e := f.c.VerifyUnstartedRestoreExec(f.ctx, r.Exec)
		if e != nil || !proof.NoProcesses || !proof.NoSessions || !proof.ExecNeverStarted {
			t.Fatal(proof, e)
		}
	})
}

func TestPostgresEmptySourceAliasesAndCatalogGates(t *testing.T) {
	f := realPGFixture(t)
	src := f.container("empty-source")
	f.sql(src, "postgres", `CREATE DATABASE empty_source TEMPLATE template0`)
	repo, snap := captureSnapshot(t, f, src, "empty_source")
	alias, e := f.c.CaptureSource(f.ctx, src.ContainerID[:12])
	if e != nil {
		t.Fatal(e)
	}
	if alias != src {
		t.Fatal("alias did not resolve to immutable ID")
	}
	called := false
	opts := RestoreOptions{PersistExec: func(docker.RestoreExec) error { called = true; return nil }}
	r, e := RestorePostgres(f.ctx, repo, snap, f.c, alias, "empty_source", "postgres", opts)
	if e == nil || called || !strings.Contains(e.Error(), "physical fingerprint") {
		t.Fatalf("empty source alias accepted %+v %v checkpoint=%v", r, e, called)
	}
	t.Log("empty source alias rejected by cluster-system-ID + database OID", e)
	cases := []struct{ name, sql string }{
		{"extra-empty-schema", `CREATE SCHEMA outside`},
		{"outside-table", `CREATE SCHEMA outside; CREATE TABLE outside.t(i int)`},
		{"outside-view", `CREATE SCHEMA outside; CREATE VIEW outside.v AS SELECT 1`},
		{"outside-sequence", `CREATE SCHEMA outside; CREATE SEQUENCE outside.s`},
		{"outside-function", `CREATE SCHEMA outside; CREATE FUNCTION outside.f() RETURNS int LANGUAGE sql AS 'SELECT 1'`},
		{"outside-domain", `CREATE SCHEMA outside; CREATE DOMAIN outside.d AS int`},
		{"outside-enum", `CREATE SCHEMA outside; CREATE TYPE outside.e AS ENUM('a')`},
		{"outside-composite", `CREATE SCHEMA outside; CREATE TYPE outside.c AS (a int)`},
		{"outside-collation", `CREATE SCHEMA outside; CREATE COLLATION outside.c FROM "C"`},
		{"text-search", `CREATE SCHEMA outside; CREATE TEXT SEARCH CONFIGURATION outside.c (COPY=pg_catalog.english)`},
		{"schema-default-ACL", `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC`},
		{"global-default-ACL", `ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC`},
		{"extra-extension", `CREATE EXTENSION hstore`},
		{"schema-ACL-drift", `REVOKE USAGE ON SCHEMA public FROM PUBLIC`},
		{"large-object", `SELECT lo_create(33333)`},
		{"global-cast-between-system-types", `CREATE CAST (boolean AS date) WITH INOUT`},
		{"global-access-method", `CREATE ACCESS METHOD bakabel_heap TYPE TABLE HANDLER pg_catalog.heap_tableam_handler`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := fmt.Sprintf("dirty_%d", i)
			f.sql(src, "postgres", "CREATE DATABASE "+qid(db)+" TEMPLATE template0")
			f.sql(src, db, tc.sql)
			p, e := f.c.PrepareRestorePostgres(f.ctx, src, db, "postgres")
			if e != nil {
				t.Fatal(e)
			}
			if e = f.c.CheckRestoreEmpty(f.ctx, p); e == nil {
				t.Fatal("dirty full catalog accepted")
			}
			called = false
			r, e := RestorePostgres(f.ctx, repo, snap, f.c, src, db, "postgres", opts)
			if e == nil || called || r.Status == "restored" {
				t.Fatal("dirty import started", r, e, called)
			}
		})
	}
	t.Run("missing-identity-permission", func(t *testing.T) {
		f.sql(src, "postgres", `CREATE ROLE limited LOGIN`)
		f.sql(src, "empty_source", `REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC`)
		// Query as a non-superuser after an actual execute revoke: authentic server error.
		conn := strings.Replace(testConn("empty_source"), "user='postgres'", "user='limited'", 1)
		id, e := f.c.CreateExec(f.ctx, src.ContainerID, docker.ExecConfig{User: "0", Cmd: []string{"/usr/local/bin/psql", "-XAt", "-v", "ON_ERROR_STOP=1", "--dbname", conn, "-c", "SELECT system_identifier FROM pg_catalog.pg_control_system()"}})
		if e != nil {
			t.Fatal(e)
		}
		if e = f.c.StartExec(f.ctx, id, io.Discard, io.Discard); e != nil {
			t.Fatal(e)
		}
		code, e := f.c.WaitExec(f.ctx, id)
		if e != nil || code == 0 {
			t.Fatal("identity permission unexpectedly available", code, e)
		}
		if _, e = f.c.PrepareRestorePostgres(f.ctx, src, "empty_source", "limited"); e == nil {
			t.Fatal("unverifiable identity accepted")
		}
		t.Logf("actual identity denied psql exit=%d; no grants/roles auto-repaired", code)
	})
}
