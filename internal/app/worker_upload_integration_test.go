package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConcreteUploadFailureUsesBoundedWorkerDeadline(t *testing.T) {
	f := realFixture(t)
	f.sql("CREATE TABLE bulk AS SELECT g,(SELECT string_agg(md5(g::text||':'||s::text),'') FROM generate_series(1,32)s) AS data FROM generate_series(1,50000)g")
	l := workerLaunchFixture(t, f)
	l.Timeout = 4 * time.Second
	proxy := newRawProxy(t, f.socket, true, nil)
	l.Socket = hostPath(proxy.socket)
	o := newOwner(t)
	w, e := LaunchPostgresWorker(f.ctx, o, f.c, f.p, l)
	if e != nil {
		t.Fatal(e)
	}
	cleanupConcreteWorker(t, f, w)
	select {
	case <-proxy.seen:
	case <-time.After(15 * time.Second):
		t.Fatal("actual source never streamed")
	}
	// Fault only this disposable repository's data pathname. Unlike renaming the
	// mount root, this is visible through the worker's existing repository bind.
	data := filepath.Join(l.RepositoryDir, "data")
	offline := data + ".offline"
	if e = os.Rename(data, offline); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(data, []byte("disposable backend write fault"), 0600); e != nil {
		t.Fatal(e)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		if e := os.Remove(data); e != nil {
			t.Error(e)
		}
		if e := os.Rename(offline, data); e != nil {
			t.Error(e)
		}
		restored = true
	}
	defer restore()
	start := time.Now()
	result, proof, e := FinishWorker(f.ctx, o, f.c, l.JobDir)
	if e == nil || result.Error != "backup failed" || result.Status == "complete" || result.SnapshotID != "" || !proof.NoProcesses || !proof.NoSessions {
		t.Fatal("backend failure lacked bounded receipt/source proof", result, proof, e)
	}
	if elapsed := time.Since(start); elapsed > 27*time.Second {
		t.Fatal("backend retries escaped worker/cleanup bounds", elapsed)
	}
	restore()
	snaps, e := repositoryForLaunch(l).Snapshots(f.ctx)
	if e != nil || len(snaps) != 0 {
		t.Fatal("backend fault committed snapshot", snaps, e)
	}
	t.Logf("actual backend write fault: worker_deadline=4s elapsed=%s fixed_error=%q snapshots=0 source_processes=0 sessions=0", time.Since(start), result.Error)
}
