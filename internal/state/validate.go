package state

import (
	"errors"
	"time"
)

var ErrInvalid = errors.New("invalid state record or transition")
var ErrCorrupt = errors.New("corrupt or unsupported durable state; ownership blocked")

func token(s string, required bool) bool {
	if len(s) == 0 {
		return !required
	}
	if len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}
func validate(r Record) error {
	if r.ExecKind != "" && r.ExecKind != "dump" && r.ExecKind != "restore" {
		return ErrInvalid
	}
	if !token(r.ImportRunID, false) || (r.ImportRunID != "" && (r.ExecKind != "restore" || r.ImportRunID == r.RunID)) {
		return ErrInvalid
	}
	if r.ExecKind == "restore" && (r.Phase == PhaseExecCreated || r.Phase == PhaseExecStarted) && r.ImportRunID == "" {
		return ErrInvalid
	}
	if r.WorkerStartAuthorized && r.WorkerContainerID == "" {
		return ErrInvalid
	}
	if !token(r.RunID, true) || !token(r.DaemonID, true) || !token(r.WorkerName, true) || !token(r.WorkerContainerID, false) || !token(r.TargetID, false) || !token(r.SourceContainerID, false) || !token(r.ExecID, false) {
		return ErrInvalid
	}
	if (r.SourceContainerID == "") != (r.SourceStartedAt == "") {
		return ErrInvalid
	}
	if r.SourceStartedAt != "" {
		if len(r.SourceStartedAt) > 64 {
			return ErrInvalid
		}
		if _, e := time.Parse(time.RFC3339Nano, r.SourceStartedAt); e != nil {
			return ErrInvalid
		}
	}
	if r.Phase == PhaseQuarantine {
		if r.Status != StatusBlocked {
			return ErrInvalid
		}
		return nil
	}
	if r.Status != StatusActive {
		return ErrInvalid
	}
	switch r.Phase {
	case PhaseIntent:
		if r.ExecID != "" {
			return ErrInvalid
		}
	case PhaseCreatingExec:
		if r.SourceContainerID == "" || r.ExecID != "" {
			return ErrInvalid
		}
	case PhaseExecCreated, PhaseExecStarted:
		if r.SourceContainerID == "" || r.ExecID == "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validateTransition(a, b Record) error {
	if e := validate(b); e != nil {
		return e
	}
	if a.RunID != b.RunID || a.DaemonID != b.DaemonID || a.WorkerName != b.WorkerName {
		return ErrInvalid
	}
	for _, pair := range [][2]string{{a.ExecKind, b.ExecKind}, {a.ImportRunID, b.ImportRunID}, {a.WorkerContainerID, b.WorkerContainerID}, {a.TargetID, b.TargetID}, {a.SourceContainerID, b.SourceContainerID}, {a.SourceStartedAt, b.SourceStartedAt}, {a.ExecID, b.ExecID}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return ErrInvalid
		}
	}
	if a.WorkerStartAuthorized && !b.WorkerStartAuthorized {
		return ErrInvalid
	}
	if a.Phase == PhaseQuarantine {
		// Recovery may retain a concretely verified ID after create response loss.
		if a.WorkerContainerID == "" && !a.WorkerStartAuthorized {
			a.WorkerContainerID = b.WorkerContainerID
		}
		if a != b {
			return ErrInvalid
		}
		return nil
	}
	if b.Phase == PhaseQuarantine {
		return nil
	}
	if a.Phase == b.Phase {
		return nil
	}
	if a.Phase == PhaseIntent && b.Phase == PhaseCreatingExec || a.Phase == PhaseCreatingExec && b.Phase == PhaseExecCreated || a.Phase == PhaseExecCreated && b.Phase == PhaseExecStarted {
		return nil
	}
	return ErrInvalid
}
