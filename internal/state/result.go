package state

import (
	"errors"
	"os"
	"syscall"
	"time"
)

var ErrNoResult = errors.New("no last result")

type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomeFailed   Outcome = "failed"
	OutcomeCanceled Outcome = "canceled"
	OutcomeUnknown  Outcome = "unknown"
)

// Result is the last caller-reported outcome, not proof of resource termination.
type Result struct {
	RunID               string  `json:"runID"`
	Status              Outcome `json:"status"`
	Operation           string  `json:"operation,omitempty"`
	FinishedAt          string  `json:"finishedAt,omitempty"`
	LastBackupSuccessAt string  `json:"lastBackupSuccessAt,omitempty"`
}

// TerminalProof is a caller attestation, not a Docker/SQL probe performed here.
// Both fields must be true even if a resource was proven never created.
type TerminalProof struct {
	WorkerTerminal bool
	SourceTerminal bool
}

// Release accepts the caller's explicit attestation of terminal worker AND export
// lifetime. This package cannot inspect Docker/SQL. A stale expected record is refused.
func (o *Owner) Release(expected Record, proof TerminalProof, result Result) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return ErrClosed
	}
	if o.poisoned {
		return ErrUncertain
	}
	current, e := o.load()
	if e != nil {
		return e
	}
	if current != expected || !proof.WorkerTerminal || !proof.SourceTerminal || result.RunID != current.RunID || result.FinishedAt != "" || result.LastBackupSuccessAt != "" || validateResult(result) != nil {
		return ErrInvalid
	}
	previous, e := o.lastResult()
	if e != nil && !errors.Is(e, ErrNoResult) {
		return e
	}
	result.LastBackupSuccessAt = previous.LastBackupSuccessAt
	if result.Operation != "" {
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if result.Operation == "backup" && result.Status == OutcomeSuccess {
			result.LastBackupSuccessAt = result.FinishedAt
		}
	}
	if e = o.atomicWrite("last-result.json", result); e != nil {
		return e
	}
	if e = syscall.Unlinkat(int(o.dir.Fd()), "owner.json"); e != nil {
		o.poisoned = true
		return e
	}
	if e = o.syncFile(o.dir); e != nil {
		o.poisoned = true
		return e
	}
	return nil
}

// LastResult reads the independent bounded receipt, not current ownership.
func (o *Owner) LastResult() (Result, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return Result{}, ErrClosed
	}
	return o.lastResult()
}

func (o *Owner) lastResult() (Result, error) {
	fd, e := syscall.Openat(int(o.dir.Fd()), "last-result.json", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(e, syscall.ENOENT) {
		return Result{}, ErrNoResult
	}
	if e != nil {
		return Result{}, e
	}
	f := os.NewFile(uintptr(fd), "last-result.json")
	defer f.Close()
	if e = regularPrivate(f); e != nil {
		return Result{}, e
	}
	var r Result
	if e = decodeRecord(f, MaxResultBytes, &r, "runID,status,operation,finishedAt,lastBackupSuccessAt"); e != nil {
		return Result{}, e
	}
	if validateResult(r) != nil {
		return Result{}, ErrCorrupt
	}
	return r, nil
}
func validateResult(r Result) error {
	if r.Operation != "" && r.Operation != "backup" && r.Operation != "restore" {
		return ErrInvalid
	}
	for _, value := range []string{r.FinishedAt, r.LastBackupSuccessAt} {
		if value != "" {
			if len(value) > 64 {
				return ErrInvalid
			}
			if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
				return ErrInvalid
			}
		}
	}
	if !token(r.RunID, true) {
		return ErrInvalid
	}
	switch r.Status {
	case OutcomeSuccess, OutcomeFailed, OutcomeCanceled, OutcomeUnknown:
		return nil
	default:
		return ErrInvalid
	}
}
