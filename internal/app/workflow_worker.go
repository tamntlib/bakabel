package app

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func postgresPath(source string) string {
	return "/bakabel/postgres/" + targetHash(source) + "/database.dump"
}
func workflowMetadata(p docker.Postgres, id string) backup.Metadata {
	m := postgresMetadata(p)
	m.Source = id
	m.Paths = []string{postgresPath(id)}
	return m
}

func validateWorkflowJob(j workflowJob) error {
	if j.Version != 1 || len(j.RunID) != 32 || strings.Trim(j.RunID, "0123456789abcdef") != "" || j.CreatedAt.After(time.Now().Add(time.Minute)) || j.Config.Validate() != nil || j.CreatedAt.IsZero() || len(j.Targets) == 0 || len(j.Targets) > maxWorkflowTargets {
		return errors.New("invalid workflow job")
	}
	seen := map[string]bool{}
	for _, t := range j.Targets {
		if t.ID == "" || seen[t.ID] || (t.Kind != "postgres" && t.Kind != "volume") {
			return errors.New("invalid frozen target")
		}
		seen[t.ID] = true
	}
	return nil
}

func prepareWorkflowDump(ctx context.Context, o *state.Owner, c *docker.Client, p docker.Postgres, id string) (docker.Dump, error) {
	r, e := o.Load()
	if e != nil {
		return docker.Dump{}, e
	}
	if r.Phase != state.PhaseIntent || r.SourceContainerID != "" || !r.WorkerStartAuthorized {
		return docker.Dump{}, docker.ErrQuarantine
	}
	r.TargetID = targetHash(id)
	r.SourceContainerID = p.Source.ContainerID
	r.SourceStartedAt = p.Source.StartedAt
	r.ExecKind = "dump"
	r.Phase = state.PhaseCreatingExec
	if e = o.Save(r); e != nil {
		return docker.Dump{}, e
	}
	d, e := c.CreateDump(ctx, p, r.RunID, func(d docker.Dump) error { r.ExecID = d.ExecID; r.Phase = state.PhaseExecCreated; return o.Save(r) })
	if e != nil {
		return d, quarantine(o)
	}
	return d, nil
}

func dumpTerminal(p docker.TerminalProof) bool {
	return !p.SourceTerminal && (p.ExecExitCode != nil || p.ExecNeverStarted) && p.NoProcesses && p.NoSessions
}

func backupPostgresTarget(ctx context.Context, o *state.Owner, c *docker.Client, repo backup.Repository, j workflowJob, t docker.Target) backup.Result {
	fail := func(e error) backup.Result { return backup.Result{Status: "unknown", Err: e} }
	snaps, e := repo.Snapshots(ctx)
	if e != nil {
		return fail(e)
	}
	parentArgs, e := postgresParentArgs(snaps, t.ID, files.Hostname(j.Config.Installation))
	if e != nil {
		return fail(e)
	}
	p, e := c.PreparePostgresDatabase(ctx, t.Source, t.Database)
	if e != nil {
		return fail(e)
	}
	d, e := prepareWorkflowDump(ctx, o, c, p, t.ID)
	if e != nil {
		return fail(e)
	}
	args, e := Authorize(o, workerSocket, d, time.Until(j.CreatedAt.Add(j.Config.Timeout)))
	if e != nil {
		return fail(quarantine(o))
	}
	verificationFailed := false
	repo.VerifySource = func(ctx context.Context) (err error) {
		defer func() { verificationFailed = err != nil }()
		proof, e := c.CancelDump(ctx, d)
		if e != nil || !dumpTerminal(proof) || proof.ExecExitCode == nil || *proof.ExecExitCode != 0 {
			return docker.ErrQuarantine
		}
		post, e := c.PreparePostgresDatabase(ctx, t.Source, t.Database)
		if e != nil || !reflect.DeepEqual(post.Metadata, p.Metadata) || post.Source != p.Source || post.Database != p.Database || post.User != p.User {
			return docker.ErrQuarantine
		}
		return nil
	}
	sourceArgs := append(append(parentArgs, []string{"--group-by", "host,paths", "--stdin-from-command", "--stdin-filename", postgresPath(t.ID), "--", "/usr/local/bin/bakabel"}...), args...)
	result := repo.Backup(ctx, workflowMetadata(p, t.ID), j.RunID+"-"+targetHash(t.ID), files.Hostname(j.Config.Installation), sourceArgs)
	clean, done := context.WithTimeout(context.Background(), 20*time.Second)
	defer done()
	proof, e := c.CancelDump(clean, d)
	if e != nil {
		result.Err = errors.Join(result.Err, quarantine(o))
		return result
	}
	if e = advanceDumpCheckpoint(o, proof, verificationFailed); e != nil {
		result.Err = errors.Join(result.Err, e)
	}
	return result
}

func advanceDumpCheckpoint(o *state.Owner, proof docker.TerminalProof, verificationFailed bool) error {
	if verificationFailed || !dumpTerminal(proof) {
		return quarantine(o)
	}
	r, e := o.Load()
	if e != nil {
		return e
	}
	_, e = o.AdvanceExport(r, state.TerminalProof{SourceTerminal: true})
	return e
}

func backupFileTarget(ctx context.Context, c *docker.Client, repo backup.Repository, j workflowJob, t docker.Target) backup.Result {
	fail := func(e error) backup.Result { return backup.Result{Status: "unknown", Err: e} }
	if len(t.Mounts) != 1 {
		return fail(docker.ErrQuarantine)
	}
	if len(j.Protected) == 0 {
		return fail(errors.New("protected runtime identities required for file backup"))
	}
	v, e := c.PrepareFileVolume(ctx, t.Source, t.Mounts[0].Destination)
	if e != nil || v.Mountpoint != t.Mounts[0].Source {
		return fail(docker.ErrQuarantine)
	}
	m, e := files.Capture(j.Config.Installation, t.ID, v, files.WorkerPath(t.ID, v.Destination))
	if e != nil {
		return fail(e)
	}
	repo.VerifySource = func(ctx context.Context) error {
		post, e := c.PrepareFileVolume(ctx, t.Source, v.Destination)
		if e != nil || post != v {
			return docker.ErrQuarantine
		}
		return nil
	}
	forbidden := []string{j.Config.StateDir}
	if j.Config.Repository[0] == '/' {
		forbidden = append(forbidden, j.Config.Repository)
	}
	return files.Backup(ctx, repo, m, j.RunID+"-"+targetHash(t.ID), j.Config.Installation, forbidden, j.Protected...)
}

func runWorkflow(ctx context.Context) int {
	var j workflowJob
	if readJSON(workerJobFile, &j, maxWorkflowBytes) != nil || validateWorkflowJob(j) != nil {
		return 1
	}
	c, e := docker.NewClient(workerSocket)
	if e != nil {
		return 1
	}
	defer c.Close()
	o, e := state.Acquire(j.Config.StateDir)
	if e != nil {
		return 1
	}
	defer o.Close()
	r, e := o.Load()
	if e != nil || r.RunID != j.RunID || !r.WorkerStartAuthorized || r.SourceContainerID != "" || r.Phase != state.PhaseIntent {
		return 1
	}
	hostname, e := os.Hostname()
	if e != nil {
		return 1
	}
	self, e := c.InspectContainer(ctx, hostname)
	if e != nil || self.ID != r.WorkerContainerID {
		return 1
	}
	wp, e := c.InspectWorker(ctx, recordWorker(r))
	if e != nil || wp.Worker.ContainerID != self.ID || wp.Terminal || wp.Created {
		return 1
	}
	ctx, cancel := context.WithDeadline(ctx, j.CreatedAt.Add(j.Config.Timeout))
	defer cancel()
	repo := configuredRepository(j.Config)
	result := WorkflowResult{RunID: j.RunID, Status: "complete", Targets: make([]TargetResult, 0, len(j.Targets))}
	blocked := false
	for _, t := range j.Targets {
		tr := TargetResult{TargetID: t.ID, Status: "unknown", Error: "backup failed"}
		if j.Restore != nil {
			if t.Kind == "postgres" {
				tr = restorePostgresTarget(ctx, o, c, repo, j, t)
			} else {
				tr = restoreFilesTarget(ctx, o, c, repo, j, t)
			}
		} else if !blocked && ctx.Err() == nil {
			var res backup.Result
			if t.Kind == "postgres" {
				res = backupPostgresTarget(ctx, o, c, repo, j, t)
			} else {
				res = backupFileTarget(ctx, c, repo, j, t)
			}
			tr.Status = res.Status
			tr.SnapshotID = res.SnapshotID
			if res.Err == nil && res.Status == "complete" {
				tr.Error = ""
			}
			current, err := o.Load()
			blocked = err != nil || current.Phase == state.PhaseQuarantine || current.SourceContainerID != ""
		}
		if tr.Error != "" {
			result.Status = "failed"
		}
		result.Targets = append(result.Targets, tr)
	}
	if j.Restore != nil && result.Status == "complete" {
		result.Status = "restored"
	}
	// The worker still owns the same guard and durable run here. Retention may
	// only follow a complete data run, never a restore or an uncertain export.
	retainWorkflow(ctx, repo, j, &result)
	if publishJSON(workerResultDir, "result.json", result, maxWorkflowBytes) != nil {
		return 1
	}
	if result.Status != "complete" && result.Status != "restored" {
		return 1
	}
	return 0
}

func retainWorkflow(ctx context.Context, repo backup.Repository, j workflowJob, res *WorkflowResult) {
	if res.Status != "complete" || j.Restore != nil {
		return
	}
	p := j.Config.Retention
	if err := repo.Retain(ctx, backup.Retention{Daily: p.Daily, Weekly: p.Weekly, Monthly: p.Monthly}, files.Hostname(j.Config.Installation), j.Config.Installation, true); err != nil {
		res.MaintenanceError = "retention failed"
	}
}
