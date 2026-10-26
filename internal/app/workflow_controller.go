package app

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func configuredRepository(c config.Config) backup.Repository {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "GOMAXPROCS=" + strconv.FormatInt(c.WorkerResources.Effective().CPUs, 10), "RESTIC_REPOSITORY=" + c.Repository, "RESTIC_PASSWORD_FILE=" + c.Credentials.PasswordFile}
	if c.Credentials.S3CredentialsFile != "" {
		env = append(env, "AWS_SHARED_CREDENTIALS_FILE="+c.Credentials.S3CredentialsFile)
	}
	if c.Credentials.S3Region != "" {
		env = append(env, "AWS_DEFAULT_REGION="+c.Credentials.S3Region)
	}
	return backup.Repository{Binary: "/usr/bin/restic", Env: env}
}

func loadWorkflow(c config.Config, r state.Record) (workflowJob, error) {
	var j workflowJob
	e := readJSON(filepath.Join(workflowDir(c), "job.json"), &j, maxWorkflowBytes)
	if e != nil || validateWorkflowJob(j) != nil || j.RunID != r.RunID || j.Config.Installation != c.Installation || j.Config.StateDir != c.StateDir {
		return j, docker.ErrQuarantine
	}
	return j, nil
}

func readWorkflowResult(c config.Config, j workflowJob) (WorkflowResult, error) {
	var res WorkflowResult
	if e := readJSON(filepath.Join(workflowDir(c), "output", "result.json"), &res, maxWorkflowBytes); e != nil {
		return res, e
	}
	if res.RunID != j.RunID || len(res.Targets) != len(j.Targets) || (res.Status != "complete" && res.Status != "restored" && res.Status != "failed") {
		return res, docker.ErrQuarantine
	}
	if j.Restore == nil && res.Status == "restored" || j.Restore != nil && res.Status == "complete" {
		return res, docker.ErrQuarantine
	}
	p := j.Config.Retention
	if res.MaintenanceError != "" && (res.MaintenanceError != "retention failed" || j.Restore != nil || res.Status != "complete" || p.Daily == 0 && p.Weekly == 0 && p.Monthly == 0) {
		return res, docker.ErrQuarantine
	}
	success := true
	for i, tr := range res.Targets {
		if (tr.FailureCode != "" || tr.ResticExitCode != nil || tr.ResticReason != "") && (j.Restore != nil || tr.Error != "backup failed") {
			return res, docker.ErrQuarantine
		}
		switch tr.FailureCode {
		case "", "file_preflight", "list_before", "backup", "list_after", "source_verification", "tag", "final_readback", "metadata_readback":
		default:
			return res, docker.ErrQuarantine
		}
		switch tr.ResticReason {
		case "", "enospc", "permission", "backend", "unknown":
		default:
			return res, docker.ErrQuarantine
		}
		if tr.ResticExitCode != nil && (*tr.ResticExitCode < 0 || *tr.ResticExitCode > 255) {
			return res, docker.ErrQuarantine
		}
		if j.Restore == nil && tr.Status == "restored" || j.Restore != nil && (tr.Status == "complete" || tr.SnapshotID != j.Restore.SnapshotID) {
			return res, docker.ErrQuarantine
		}
		if tr.TargetID != j.Targets[i].ID || (tr.Status != "unknown" && tr.Status != "partial" && tr.Status != "complete" && tr.Status != "restored") || (tr.Error != "" && tr.Error != "backup failed" && tr.Error != "restore failed") {
			return res, docker.ErrQuarantine
		}
		if tr.SnapshotID != "" {
			if len(tr.SnapshotID) != 64 {
				return res, docker.ErrQuarantine
			}
			for _, v := range tr.SnapshotID {
				if !(v >= '0' && v <= '9' || v >= 'a' && v <= 'f') {
					return res, docker.ErrQuarantine
				}
			}
		}
		if (tr.Status == "complete" || tr.Status == "restored") && tr.SnapshotID == "" {
			return res, docker.ErrQuarantine
		}
		if tr.Error != "" || (tr.Status != "complete" && tr.Status != "restored") {
			success = false
		}
	}
	if (res.Status == "complete" || res.Status == "restored") != success {
		return res, docker.ErrQuarantine
	}
	return res, nil
}

func verifyWorkflowSnapshots(ctx context.Context, c config.Config, j workflowJob, res WorkflowResult) error {
	snaps, e := configuredRepository(c).Snapshots(ctx)
	if e != nil {
		return e
	}
	for i, tr := range res.Targets {
		matches := 0
		for _, s := range snaps {
			if s.ID == tr.SnapshotID {
				m, e := s.Restorable()
				if e != nil {
					return e
				}
				_, status, run, e := backup.DecodeTags(s.Tags)
				t := j.Targets[i]
				if e != nil || status != "complete" || run != j.RunID+"-"+targetHash(t.ID) || m.Source != t.ID || m.Kind != t.Kind || s.Hostname != files.Hostname(c.Installation) || !reflect.DeepEqual(m.Paths, s.Paths) {
					return docker.ErrQuarantine
				}
				matches++
			}
		}
		if matches != 1 {
			return docker.ErrQuarantine
		}
	}
	return nil
}

// WorkflowCurrent adopts monitoring authority only, even while the worker owns
// its guard. A restarted scheduler may pass this handle to WorkflowWait without
// extending the durable creation-time deadline or starting/retrying anything.
func WorkflowCurrent(c config.Config) (WorkflowHandle, error) {
	r, e := state.Observe(c.StateDir)
	if e != nil {
		return WorkflowHandle{}, e
	}
	j, e := loadWorkflow(c, r)
	if e != nil {
		return WorkflowHandle{}, e
	}
	return WorkflowHandle{Worker: recordWorker(r), CreatedAt: j.CreatedAt}, nil
}

// WorkflowWait monitors WITHOUT the worker's flock. The deadline is anchored to
// the durable job CreatedAt, never renewed on controller restart. Cleanup gets a
// new bounded context. Only concrete worker terminal + source proof may release.
func WorkflowWait(ctx context.Context, c config.Config, h WorkflowHandle) (result WorkflowResult, err error) {
	defer func() {
		if result.RunID == "" {
			result.RunID = h.Worker.RunID
		}
	}()
	client, e := workflowClient(c)
	if e != nil {
		return result, e
	}
	defer client.Close()
	r, e := state.Observe(c.StateDir)
	if e != nil {
		return result, e
	}
	j, e := loadWorkflow(c, r)
	if e != nil {
		return result, e
	}
	if h.Worker != recordWorker(r) || !h.CreatedAt.Equal(j.CreatedAt) {
		return result, docker.ErrQuarantine
	}
	wait, cancel := context.WithDeadline(ctx, j.CreatedAt.Add(j.Config.Timeout))
	defer cancel()
	var wp docker.WorkerProof
	for {
		wp, e = client.InspectWorker(wait, recordWorker(r))
		if e != nil || wp.Terminal {
			break
		}
		select {
		case <-wait.Done():
			e = wait.Err()
		case <-time.After(100 * time.Millisecond):
			continue
		}
		break
	}
	clean, done := context.WithTimeout(context.Background(), 20*time.Second)
	defer done()
	return finishWorkflow(clean, c, client, wp, e == nil && wp.Terminal && wp.ExitCode == 0, h.Worker)
}

// WorkflowRecover explicitly fences/terminates the previously owned worker and
// reconciles its exact frozen active source checkpoint. It never starts a run.
// A creating-exec gap without a saved ID is quarantined, not assumed absent.
func WorkflowRecover(ctx context.Context, c config.Config) (WorkflowResult, error) {
	// Recovery remains necessary after the initiating run context is canceled;
	// preserve context values, but give concrete cleanup a fresh bounded budget.
	clean, done := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer done()
	client, e := workflowClient(c)
	if e != nil {
		return WorkflowResult{}, e
	}
	defer client.Close()
	observed, e := state.Observe(c.StateDir)
	if e != nil {
		return WorkflowResult{}, e
	}
	return finishWorkflow(clean, c, client, docker.WorkerProof{}, false, recordWorker(observed))
}

func failedWorkflow(j workflowJob) WorkflowResult {
	res := WorkflowResult{RunID: j.RunID, Status: "failed", Targets: make([]TargetResult, 0, len(j.Targets))}
	for _, t := range j.Targets {
		tr := TargetResult{TargetID: t.ID, Status: "unknown", Error: "backup failed"}
		if j.Restore != nil {
			tr.Error = "restore failed"
			tr.SnapshotID = j.Restore.SnapshotID
		}
		res.Targets = append(res.Targets, tr)
	}
	return res
}

func recoverFailureSnapshots(j workflowJob, res WorkflowResult, snaps []backup.Snapshot) WorkflowResult {
	for i, t := range j.Targets {
		matches := 0
		var exact backup.Snapshot
		var status string
		for _, s := range snaps {
			m, st, run, e := backup.DecodeTags(s.Tags)
			if e != nil || run != j.RunID+"-"+targetHash(t.ID) || m.Source != t.ID || m.Kind != t.Kind || s.Hostname != files.Hostname(j.Config.Installation) || !reflect.DeepEqual(s.Paths, m.Paths) {
				continue
			}
			matches++
			exact = s
			status = st
		}
		if matches == 1 {
			res.Targets[i].SnapshotID = exact.ID
			res.Targets[i].Status = status
		}
	}
	return res
}

func workerProofMatches(w docker.Worker, r state.Record) bool {
	return w.DaemonID == r.DaemonID && w.RunID == r.RunID && w.Name == r.WorkerName && (r.WorkerContainerID == "" || w.ContainerID == r.WorkerContainerID)
}

func finishWorkflow(ctx context.Context, c config.Config, client *docker.Client, wp docker.WorkerProof, allowSuccess bool, expected ...docker.Worker) (WorkflowResult, error) {
	var res WorkflowResult
	observed, e := state.Observe(c.StateDir)
	if e != nil {
		return res, e
	}
	if len(expected) > 1 || len(expected) == 1 && !workerProofMatches(expected[0], observed) {
		return res, docker.ErrQuarantine
	}
	w := recordWorker(observed)
	if wp.Terminal && !workerProofMatches(wp.Worker, observed) {
		return res, docker.ErrQuarantine
	}
	if !wp.Terminal {
		wp, e = client.InspectWorker(ctx, w)
		if e != nil {
			return res, e
		}
		if !wp.Created {
			wp, e = client.TerminateWorker(ctx, wp.Worker)
		}
		if e != nil || !wp.Terminal && !wp.Created {
			return res, docker.ErrQuarantine
		}
	}
	o, e := state.Acquire(c.StateDir)
	if e != nil {
		return res, e
	}
	defer o.Close()
	r, e := o.Load()
	if e != nil || r.RunID != observed.RunID || !workerProofMatches(wp.Worker, r) {
		return res, docker.ErrQuarantine
	}
	if r.WorkerContainerID == "" {
		r.WorkerContainerID = wp.Worker.ContainerID
		if e = o.Save(r); e != nil {
			return res, e
		}
	}
	if wp.Created {
		// Persist the adopted exact ID before fencing a never-running worker.
		// A crash after deletion can then prove ID+name absence on recovery.
		wp, e = client.DiscardCreatedWorker(ctx, wp.Worker)
		if e != nil || !wp.Terminal {
			return res, docker.ErrQuarantine
		}
	}
	j, e := loadWorkflow(c, r)
	if e != nil {
		return res, quarantine(o)
	}
	res, receiptErr := readWorkflowResult(c, j)
	if receiptErr != nil {
		res = failedWorkflow(j)
	}
	success := allowSuccess && r.Phase == state.PhaseIntent && r.SourceContainerID == "" && wp.ExitCode == 0 && receiptErr == nil && (res.Status == "complete" || res.Status == "restored")
	if success && j.Restore == nil {
		if e = verifyWorkflowSnapshots(ctx, c, j, res); e != nil {
			success = false
		}
	}
	if r.SourceContainerID != "" {
		var target *docker.Target
		for i := range j.Targets {
			if targetHash(j.Targets[i].ID) == r.TargetID {
				target = &j.Targets[i]
				break
			}
		}
		if target == nil || target.Kind != "postgres" || target.Source.ContainerID != r.SourceContainerID || target.Source.StartedAt != r.SourceStartedAt || r.ExecID == "" {
			return res, quarantine(o)
		}
		s := target.Source
		status, e := client.CheckSource(ctx, s)
		if e != nil {
			return res, quarantine(o)
		}
		if status != docker.SourceTerminal {
			if r.ExecKind == "restore" {
				if j.Restore == nil || r.ImportRunID == "" {
					return res, quarantine(o)
				}
				d := docker.RestoreExec{Target: s, ExecID: r.ExecID, RunID: r.ImportRunID, Database: j.Restore.Database, User: j.Restore.User}
				var proof docker.TerminalProof
				if r.Phase == state.PhaseExecCreated {
					proof, e = client.VerifyUnstartedRestoreExec(ctx, d)
				} else {
					proof, e = client.CancelRestoreExec(ctx, d)
				}
				if e != nil || !dumpTerminal(proof) {
					return res, quarantine(o)
				}
			} else {
				p, e := client.PreparePostgresDatabase(ctx, s, target.Database)
				if e != nil {
					return res, quarantine(o)
				}
				d := docker.Dump{Source: s, ExecID: r.ExecID, RunID: r.RunID, Database: p.Database, User: p.User}
				var proof docker.TerminalProof
				if r.Phase == state.PhaseExecCreated {
					proof, e = client.VerifyUnstartedDump(ctx, d)
				} else {
					proof, e = client.CancelDump(ctx, d)
				}
				if e != nil || !dumpTerminal(proof) {
					return res, quarantine(o)
				}
			}
		} else {
			success = false
		}
	} else if r.Phase != state.PhaseIntent {
		return res, quarantine(o)
	}
	if receiptErr != nil && j.Restore == nil {
		if snaps, err := configuredRepository(c).Snapshots(ctx); err == nil {
			res = recoverFailureSnapshots(j, res, snaps)
		}
	}
	outcome := state.OutcomeFailed
	if success {
		outcome = state.OutcomeSuccess
	}
	operation := "backup"
	if j.Restore != nil {
		operation = "restore"
	}
	// Retain the durable recovery anchor until exact nonforce removal and its
	// absence readback succeed. Recovery accepts an already-removed exact worker.
	if e = client.RemoveWorker(ctx, wp.Worker); e != nil {
		return res, e
	}
	if e = o.Release(r, state.TerminalProof{WorkerTerminal: true, SourceTerminal: true}, state.Result{RunID: r.RunID, Status: outcome, Operation: operation}); e != nil {
		return res, e
	}
	if !success {
		res.Status = "failed"
		return res, errors.New("workflow failed")
	}
	if res.MaintenanceError != "" {
		return res, errors.New("retention failed")
	}
	return res, nil
}

// Run is the shared one-shot API for CLI and the scheduler. No cron/dependency
// ownership is hidden here: callers schedule this exact function themselves.
func Run(ctx context.Context, c config.Config) (WorkflowResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	h, e := WorkflowStart(ctx, c)
	return reconcileWorkflowLaunch(ctx, c, h, e)
}

// Backup and both restore paths retain exact launch authority across a lost
// response. Never retry create/start or reconcile a different owner's run.
func reconcileWorkflowLaunch(ctx context.Context, c config.Config, h WorkflowHandle, launchErr error) (WorkflowResult, error) {
	if launchErr == nil {
		return WorkflowWait(ctx, c, h)
	}
	if h.Worker.RunID == "" {
		return WorkflowResult{}, launchErr
	}
	result := WorkflowResult{RunID: h.Worker.RunID, Status: "failed"}
	clean, done := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer done()
	client, clientErr := workflowClient(c)
	if clientErr != nil {
		return result, errors.Join(launchErr, clientErr)
	}
	defer client.Close()
	reconciled, recoveryErr := finishWorkflow(clean, c, client, docker.WorkerProof{}, false, h.Worker)
	if reconciled.RunID != "" {
		result = reconciled
	}
	return result, errors.Join(launchErr, recoveryErr)
}
