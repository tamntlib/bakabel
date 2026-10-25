package state

import (
	"errors"
	"testing"
)

func TestWorkerAuthorizationRequiresDurableID(t *testing.T) {
	o, e := Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := Record{RunID: "run", DaemonID: "daemon", WorkerName: "random", Phase: PhaseIntent, Status: StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.WorkerStartAuthorized = true
	if e = o.Save(r); !errors.Is(e, ErrInvalid) {
		t.Fatal("start authorized without ID", e)
	}
	r.WorkerStartAuthorized = false
	r.WorkerContainerID = "exact"
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.WorkerStartAuthorized = true
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.WorkerStartAuthorized = false
	if e = o.Save(r); !errors.Is(e, ErrInvalid) {
		t.Fatal("start authorization forgotten", e)
	}
}
func TestQuarantinedWorkerCreateLossCanAdoptExactID(t *testing.T) {
	o, e := Acquire(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := Record{RunID: "run", DaemonID: "daemon", WorkerName: "random", Phase: PhaseIntent, Status: StatusActive}
	if e = o.NewRun(r); e != nil {
		t.Fatal(e)
	}
	r.Phase = PhaseQuarantine
	r.Status = StatusBlocked
	if e = o.Save(r); e != nil {
		t.Fatal(e)
	}
	r.WorkerContainerID = "verified"
	if e = o.Save(r); e != nil {
		t.Fatal("verified create-loss identity cannot be retained", e)
	}
	r.WorkerContainerID = "other"
	if e = o.Save(r); !errors.Is(e, ErrInvalid) {
		t.Fatal("identity drift accepted", e)
	}
}
