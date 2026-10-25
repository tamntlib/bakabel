package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func hostPath(p string) string {
	return strings.Replace(p, "/wtmp/", os.Getenv("BAKABEL_TEST_HOST_TMP")+"/", 1)
}
func workerLaunchFixture(t *testing.T, f *fixture) WorkerLaunch {
	t.Helper()
	dir := t.TempDir()
	job := filepath.Join(dir, "job")
	if e := os.Mkdir(job, 0700); e != nil {
		t.Fatal(e)
	}
	r := repoFixture(t, f.ctx)
	var pass, repository string
	for _, v := range r.Env {
		if strings.HasPrefix(v, "RESTIC_PASSWORD_FILE=") {
			pass = strings.TrimPrefix(v, "RESTIC_PASSWORD_FILE=")
		}
		if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
			repository = strings.TrimPrefix(v, "RESTIC_REPOSITORY=")
		}
	}
	return WorkerLaunch{Image: os.Getenv("BAKABEL_WORKER_IMAGE"), Socket: f.socket, JobDir: hostPath(job), RepositoryDir: hostPath(repository), PasswordFile: hostPath(pass), Timeout: 45 * time.Second}
}
func cleanupConcreteWorker(t *testing.T, f *fixture, w docker.Worker) {
	t.Helper()
	t.Cleanup(func() {
		// Nonforce cleanup, only after concrete proof; a live/uncertain worker is left owned.
		proof, e := f.c.TerminateWorker(f.ctx, w)
		if e != nil || !proof.Terminal {
			t.Error("worker cleanup proof", proof, e)
			return
		}
		if e := f.c.RemoveWorker(f.ctx, w); e != nil {
			t.Error("concrete nonforce worker cleanup", e)
		}
		if code := f.api("GET", "/containers/"+w.ContainerID+"/json", nil, nil); code != 404 {
			t.Error("worker removal readback", code)
		}
	})
}
func repositoryForLaunch(l WorkerLaunch) backup.Repository {
	conv := func(p string) string { return strings.Replace(p, os.Getenv("BAKABEL_TEST_HOST_TMP")+"/", "/wtmp/", 1) }
	return backup.Repository{Binary: os.Getenv("RESTIC_TEST_BINARY"), Env: append(os.Environ(), "RESTIC_REPOSITORY="+conv(l.RepositoryDir), "RESTIC_PASSWORD_FILE="+conv(l.PasswordFile))}
}
func TestConcreteWorkerSuccess(t *testing.T) {
	f := realFixture(t)
	l := workerLaunchFixture(t, f)
	o := newOwner(t)
	w, e := LaunchPostgresWorker(f.ctx, o, f.c, f.p, l)
	if e != nil {
		t.Fatal("launch", e)
	}
	cleanupConcreteWorker(t, f, w)
	var actual struct {
		Config struct{ Env, Cmd, Entrypoint []string }
		Mounts []docker.Mount
	}
	f.api("GET", "/containers/"+w.ContainerID+"/json", nil, &actual)
	if strings.Contains(strings.Join(append(append(actual.Config.Env, actual.Config.Cmd...), actual.Config.Entrypoint...), " "), "disposable-test-only") {
		t.Fatal("credential leaked in Docker Config")
	}
	mounts := map[string]docker.Mount{}
	for _, m := range actual.Mounts {
		mounts[m.Destination] = m
	}
	if len(mounts) != 5 || mounts[workerJobFile].RW || mounts[workerPassword].RW || mounts[workerSocket].RW || !mounts[workerResultDir].RW || !mounts["/repository"].RW {
		t.Fatal("actual worker mounts violate explicit permissions", actual.Mounts)
	}
	jobStat, e := os.Stat(filepath.Join(l.JobDir, "job.json"))
	if e != nil || jobStat.Size() > 16384 {
		t.Fatal("job JSON not bounded", jobStat, e)
	}
	r, e := o.Load()
	if e != nil || r.WorkerContainerID != w.ContainerID || !r.WorkerStartAuthorized || r.ExecID == "" {
		t.Fatal("worker launched before durable identity", r, e)
	}
	result, proof, e := FinishWorker(f.ctx, o, f.c, l.JobDir)
	if e != nil || result.Status != "complete" || len(result.SnapshotID) != 64 || proof.ExecExitCode == nil || *proof.ExecExitCode != 0 || !proof.NoProcesses || !proof.NoSessions {
		t.Fatalf("result=%+v proof=%+v err=%v", result, proof, e)
	}
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("not released", e)
	}
	// Repository readback independent of the worker's persisted receipt.
	repo := repositoryForLaunch(l)
	snaps, e := repo.Snapshots(f.ctx)
	if e != nil || len(snaps) != 1 || snaps[0].ID != result.SnapshotID {
		t.Fatal("snapshot readback", snaps, e)
	}
	var dump bytes.Buffer
	if e = repo.Dump(f.ctx, result.SnapshotID, "/postgres.dump", &dump); e != nil || !bytes.HasPrefix(dump.Bytes(), []byte("PGDMP")) {
		t.Fatal("actual custom dump", e)
	}
	v, e := f.c.InspectContainer(f.ctx, f.id)
	if e != nil || !v.State.Running || v.State.StartedAt != f.p.Source.StartedAt || v.RestartCount != 0 {
		t.Fatal("source lifecycle changed", v.State, e)
	}
	t.Logf("worker=%s exact finalID=%s dump_bytes=%d source_exit=0 processes=0 sessions=0", w.ContainerID, result.SnapshotID, dump.Len())
}
