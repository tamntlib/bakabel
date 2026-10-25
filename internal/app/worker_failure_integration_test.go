package app

import (
	"testing"
	"time"
)

func TestConcreteWorkerFailureRecordsFixedBoundedReceipt(t *testing.T) {
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
	f.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='" + w.RunID + "'")
	result, proof, e := FinishWorker(f.ctx, o, f.c, l.JobDir)
	if e == nil || result.RunID != w.RunID || result.Status == "complete" || result.Error != "backup failed" || result.SnapshotID != "" || !proof.NoProcesses || !proof.NoSessions {
		t.Fatal("failed worker receipt/termination", result, proof, e)
	}
	snaps, e := repositoryForLaunch(l).Snapshots(f.ctx)
	if e != nil || len(snaps) != 0 {
		t.Fatal("failed producer committed snapshot", snaps, e)
	}
	t.Logf("actual failed worker persisted status=%s snapshotID=%q error=%q; no source processes/sessions", result.Status, result.SnapshotID, result.Error)
}
