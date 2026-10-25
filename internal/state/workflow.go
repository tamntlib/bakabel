package state

// ObserveResult reads the bounded atomic outcome without acquiring a launcher
// guard or creating files. It grants no authority to launch or release a run.
func ObserveResult(dir string) (Result, error) {
	d, err := openDirectory(dir)
	if err != nil {
		return Result{}, err
	}
	defer d.Close()
	return (&Owner{dir: d}).lastResult()
}

// Observe reads an atomic record without acquiring the launcher guard. It grants
// no mutation/launch authority and is only for monitoring an active worker.
func Observe(dir string) (Record, error) {
	d, err := openDirectory(dir)
	if err != nil {
		return Record{}, err
	}
	defer d.Close()
	return (&Owner{dir: d}).load()
}

// AdvanceExport resets ONLY the active source checkpoint, never workflow/worker
// ownership. The caller must have independently proved this exact export and its
// source sessions terminal before moving to the next sequential target. This is
// not a backup-success attestation and does not release the launcher guard.
func (o *Owner) AdvanceExport(expected Record, proof TerminalProof) (Record, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lock == nil {
		return Record{}, ErrClosed
	}
	if o.poisoned {
		return Record{}, ErrUncertain
	}
	old, err := o.load()
	if err != nil {
		return Record{}, err
	}
	if old != expected || old.Phase != PhaseExecStarted || old.Status != StatusActive || !old.WorkerStartAuthorized || !proof.SourceTerminal {
		return Record{}, ErrInvalid
	}
	next := old
	next.SourceContainerID = ""
	next.TargetID = ""
	next.SourceStartedAt = ""
	next.ExecID = ""
	next.ExecKind = ""
	next.ImportRunID = ""
	next.Phase = PhaseIntent
	if err = validate(next); err != nil {
		return Record{}, err
	}
	if err = o.atomicWrite("owner.json", next); err != nil {
		return Record{}, err
	}
	return next, nil
}
