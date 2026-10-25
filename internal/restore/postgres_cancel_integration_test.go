package restore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

type restoreWorkerJob struct {
	Repo                 backup.Repository
	Snapshot             backup.Snapshot
	Target               docker.Source
	Database, Checkpoint string
}

func TestPostgresRestoreWorkerFixtureProcess(t *testing.T) {
	raw := os.Getenv("BAKABEL_B2_RESTORE_JOB")
	if raw == "" {
		return
	}
	var job restoreWorkerJob
	if json.Unmarshal([]byte(raw), &job) != nil {
		os.Exit(2)
	}
	c, e := docker.NewClient(os.Getenv("BAKABEL_B2_SOCKET"))
	if e != nil {
		os.Exit(2)
	}
	r, e := RestorePostgres(context.Background(), job.Repo, job.Snapshot, c, job.Target, job.Database, "postgres", RestoreOptions{PersistExec: func(d docker.RestoreExec) error {
		b, e := json.Marshal(d)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(job.Checkpoint, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		if _, e = f.Write(b); e != nil {
			f.Close()
			return e
		}
		if e = f.Sync(); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		dir, e := os.Open(filepath.Dir(job.Checkpoint))
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	}})
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		os.Exit(2)
	}
	if e != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func waitRestoreSleep(t *testing.T, f pgFixture, d docker.RestoreExec) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got := f.sql(d.Target, d.Database, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+d.RunID+"' AND wait_event='PgSleep'")
		if got == "1" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("target pg_restore did not enter real active backend sleep")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPostgresActualCancellationAndWorkerDeath(t *testing.T) {
	f := realPGFixture(t)
	src := f.container("cancel-source")
	// The dump defines a real check-constraint function: source insert is quick;
	// pg_restore's COPY sleeps inside the server, leaving an active backend to end.
	f.sql(src, "postgres", `CREATE FUNCTION public.slow_check(i int) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF current_setting('application_name') LIKE 'restore_%' THEN PERFORM pg_sleep(90); END IF; RETURN true; END $$; CREATE TABLE public.payload(i int CHECK(slow_check(i))); INSERT INTO payload VALUES(1)`)
	repo, snap := captureSnapshot(t, f, src, "postgres")
	if e := f.api("DELETE", "/containers/"+src.ContainerID+"?force=true&v=true", nil, nil); e != nil {
		t.Fatal(e)
	}
	dst := f.container("cancel-target")
	t.Run("caller-context-cancel-ends-import-and-active-server-query", func(t *testing.T) {
		db := "ctx cancel"
		f.sql(dst, "postgres", "CREATE DATABASE "+qid(db)+" TEMPLATE template0")
		active := make(chan docker.RestoreExec, 1)
		done := make(chan struct {
			r PostgresResult
			e error
		}, 1)
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		go func() {
			r, e := RestorePostgres(ctx, repo, snap, f.c, dst, db, "postgres", RestoreOptions{PersistExec: func(d docker.RestoreExec) error { active <- d; return nil }})
			done <- struct {
				r PostgresResult
				e error
			}{r, e}
		}()
		var d docker.RestoreExec
		select {
		case d = <-active:
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		}
		waitRestoreSleep(t, f, d)
		cancel()
		select {
		case got := <-done:
			if got.e == nil || !errors.Is(got.e, context.Canceled) || got.r.Status == "restored" || !got.r.Terminal.NoProcesses || !got.r.Terminal.NoSessions || got.r.ImportExitCode == nil || *got.r.ImportExitCode == 0 {
				t.Fatalf("cancel result %+v %v", got.r, got.e)
			}
			t.Logf("real context cancellation exec=%s exit=%d active backend gone, partial target retained", d.ExecID, *got.r.ImportExitCode)
		case <-time.After(20 * time.Second):
			t.Fatal("cancellation failed to finish bounded cleanup")
		}
		if f.sql(dst, db, `SELECT to_regclass('public.payload') IS NOT NULL`) != "t" {
			t.Fatal("target auto-dropped")
		}
	})
	t.Run("worker-SIGKILL-fresh-controller-recovers-checkpoint", func(t *testing.T) {
		db := "worker dies"
		f.sql(dst, "postgres", "CREATE DATABASE "+qid(db)+" TEMPLATE template0")
		cp := filepath.Join(t.TempDir(), "active.json")
		job := restoreWorkerJob{repo, snap, dst, db, cp}
		raw, _ := json.Marshal(job)
		bin, _ := os.Executable()
		cmd := exec.Command(bin, "-test.run=^TestPostgresRestoreWorkerFixtureProcess$")
		cmd.Env = append(os.Environ(), "BAKABEL_B2_RESTORE_JOB="+string(raw))
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		})
		var d docker.RestoreExec
		deadline := time.Now().Add(20 * time.Second)
		for {
			b, e := os.ReadFile(cp)
			if e == nil && json.Unmarshal(b, &d) == nil && d.ExecID != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("durable create-before-start checkpoint missing")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if d.Target != dst || d.Database != db || d.RunID == "" || d.User != "postgres" {
			t.Fatal("wrong checkpoint", d)
		}
		waitRestoreSleep(t, f, d)
		if e := cmd.Process.Kill(); e != nil {
			t.Fatal(e)
		}
		if e := cmd.Wait(); e == nil {
			t.Fatal("worker kill returned success")
		}
		fresh, e := docker.NewClient(f.socket)
		if e != nil {
			t.Fatal(e)
		}
		state, e := fresh.PollExec(f.ctx, d.ExecID)
		if e != nil || !state.Running {
			t.Fatal("worker death incorrectly stopped external target exec", state, e)
		}
		wrong := d
		wrong.RunID = "restore_not_owned_0123456789"
		if _, e = fresh.CancelRestoreExec(f.ctx, wrong); !errors.Is(e, docker.ErrQuarantine) {
			t.Fatal("wrong token not quarantined", e)
		}
		wrong = d
		wrong.Database = "postgres"
		if _, e = fresh.CancelRestoreExec(f.ctx, wrong); !errors.Is(e, docker.ErrQuarantine) {
			t.Fatal("wrong literal DB did not fail fixed argv check", e)
		}
		state, e = fresh.PollExec(f.ctx, d.ExecID)
		if e != nil || !state.Running {
			t.Fatal("unowned cancellation affected import", state, e)
		}
		disconnected, _ := docker.NewClient(filepath.Join(t.TempDir(), "missing.sock"))
		if _, e = disconnected.CancelRestoreExec(f.ctx, d); !errors.Is(e, docker.ErrQuarantine) {
			t.Fatal("disconnect released ownership", e)
		}
		proof, e := fresh.CancelRestoreExec(f.ctx, d)
		if e != nil || !proof.NoProcesses || !proof.NoSessions || proof.ExecExitCode == nil || *proof.ExecExitCode == 0 {
			t.Fatal("fresh-controller target terminal proof", proof, e)
		}
		if f.sql(dst, db, `SELECT to_regclass('public.payload') IS NOT NULL`) != "t" {
			t.Fatal("partial target not retained")
		}
		state, e = fresh.PollExec(f.ctx, d.ExecID)
		if e != nil || state.Running {
			t.Fatal("target exec not terminal", state, e)
		}
		// The checkpoint has only target/exec/token/literal DB/user, no repository
		// password, dump bytes, or dependency on the removed source/state.
		b, _ := os.ReadFile(cp)
		if strings.Contains(string(b), "disposable-b2-fixture") || strings.Contains(string(b), "repository") {
			t.Fatal("checkpoint leaked credentials")
		}
		t.Logf("worker SIGKILL checkpoint=%s exec=%s target import exit=%d processes=0 sessions=0; wrong token/DB refused", fmt.Sprint(d.Target.ContainerID), d.ExecID, *proof.ExecExitCode)
	})
}
