package state

import "testing"

func TestRestoreCheckpointKeepsIndependentImportIdentity(t *testing.T) {
	dir := t.TempDir()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := Record{RunID: "overall", DaemonID: "daemon", WorkerName: "worker", WorkerContainerID: "workerid", WorkerStartAuthorized: true, Phase: PhaseIntent, Status: StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.SourceContainerID = "target"
	r.SourceStartedAt = "2026-01-01T00:00:00Z"
	r.TargetID = "targethash"
	r.ExecKind = "restore"
	r.Phase = PhaseCreatingExec
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.ImportRunID = "restore_independent_random_token"
	r.ExecID = "exec"
	r.Phase = PhaseExecCreated
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	got, e := Observe(dir)
	if e != nil || got != r {
		t.Fatal(got, e)
	}
	bad := r
	bad.ImportRunID = "other"
	if o.Save(bad) == nil {
		t.Fatal("import token mutation accepted")
	}
	r.Phase = PhaseExecStarted
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	next, e := o.AdvanceExport(r, TerminalProof{SourceTerminal: true})
	if e != nil {
		t.Fatal(e)
	}
	if next.ImportRunID != "" || next.ExecKind != "" || next.ExecID != "" || next.RunID != "overall" {
		t.Fatal(next)
	}
}
