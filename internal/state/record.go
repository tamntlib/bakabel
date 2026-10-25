package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

var ErrNoRun = errors.New("no durable run owner")
var ErrOwned = errors.New("durable run owner exists")

type Phase string
type Status string

const PhaseIntent Phase = "intent"
const PhaseCreatingExec Phase = "creating_exec"
const PhaseExecCreated Phase = "exec_created"
const PhaseExecStarted Phase = "exec_started"
const PhaseQuarantine Phase = "quarantine"
const StatusBlocked Status = "blocked"
const StatusActive Status = "active"

// Save durably advances only the same run, retaining every established identity.
// It never creates ownership or resumes a quarantined run.
func (o *Owner) Save(record Record) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return ErrClosed
	}
	old, err := o.load()
	if err != nil {
		return err
	}
	if err := validateTransition(old, record); err != nil {
		return err
	}
	if o.poisoned {
		return ErrUncertain
	}
	return o.atomicWrite("owner.json", record)
}

// Record stores only bounded runtime identifiers, never credentials or free text.
// An exec_created record does not prove the exec has never started.
type Record struct {
	RunID                 string `json:"runID"`
	DaemonID              string `json:"daemonID"`
	WorkerName            string `json:"workerName"`
	WorkerContainerID     string `json:"workerContainerID,omitempty"`
	WorkerStartAuthorized bool   `json:"workerStartAuthorized,omitempty"`
	TargetID              string `json:"targetID,omitempty"`
	ExecKind              string `json:"execKind,omitempty"`
	ImportRunID           string `json:"importRunID,omitempty"`
	SourceContainerID     string `json:"sourceContainerID,omitempty"`
	SourceStartedAt       string `json:"sourceStartedAt,omitempty"`
	ExecID                string `json:"execID,omitempty"`
	Phase                 Phase  `json:"phase"`
	Status                Status `json:"status"`
}

// NewRun atomically publishes initial intent while holding the launcher guard.
// Only its successful return permits external worker/exec side effects.
func (o *Owner) NewRun(record Record) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return ErrClosed
	}
	if err := validate(record); err != nil {
		return err
	}
	if record.Phase != PhaseIntent {
		return ErrInvalid
	}
	if o.poisoned {
		return ErrUncertain
	}
	fd, err := syscall.Openat(int(o.dir.Fd()), "owner.json", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		syscall.Close(fd)
		return ErrOwned
	}
	if !errors.Is(err, syscall.ENOENT) {
		return ErrOwned
	}
	return o.atomicWrite("owner.json", record)
}

// Load reads and validates the bounded durable owner; errors never authorize a run.
func (o *Owner) Load() (Record, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return Record{}, ErrClosed
	}
	return o.load()
}
func (o *Owner) load() (Record, error) {
	fd, err := syscall.Openat(int(o.dir.Fd()), "owner.json", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ENOENT) {
		return Record{}, ErrNoRun
	}
	if err != nil {
		return Record{}, err
	}
	f := os.NewFile(uintptr(fd), "owner.json")
	defer f.Close()
	if err := regularPrivate(f); err != nil {
		return Record{}, err
	}
	var record Record
	if err = decodeRecord(f, MaxRecordBytes, &record, "runID,daemonID,workerName,workerContainerID,workerStartAuthorized,targetID,execKind,importRunID,sourceContainerID,sourceStartedAt,execID,phase,status"); err != nil {
		return Record{}, err
	}
	if err := validate(record); err != nil {
		return Record{}, fmt.Errorf("%w: invalid record", ErrCorrupt)
	}
	return record, nil
}
