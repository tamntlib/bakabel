package app

import (
	"context"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
	"time"
)

// Prepare persists intended helper identity and creating_exec BEFORE Docker create;
// CreateDump's callback durably saves ExecID before any start can be authorized.
func Prepare(ctx context.Context, o *state.Owner, c *docker.Client, p docker.Postgres, run, worker string) (docker.Dump, error) {
	r := state.Record{RunID: run, DaemonID: p.Source.DaemonID, WorkerName: worker, Phase: state.PhaseIntent, Status: state.StatusActive}
	if e := o.NewRun(r); e != nil {
		return docker.Dump{}, e
	}
	r.SourceContainerID = p.Source.ContainerID
	r.SourceStartedAt = p.Source.StartedAt
	r.Phase = state.PhaseCreatingExec
	if e := o.Save(r); e != nil {
		return docker.Dump{}, e
	}
	d, e := c.CreateDump(ctx, p, run, func(d docker.Dump) error { r.ExecID = d.ExecID; r.Phase = state.PhaseExecCreated; return o.Save(r) })
	if e != nil {
		current, le := o.Load()
		if le != nil {
			return d, le
		}
		current.Phase = state.PhaseQuarantine
		current.Status = state.StatusBlocked
		if se := o.Save(current); se != nil {
			return d, se
		}
	}
	return d, e
}

// Authorize durably records start authorization BEFORE the caller spawns Restic
// or the helper. PhaseExecStarted is authorization, not evidence of external start.
func Authorize(o *state.Owner, socket string, d docker.Dump, timeout time.Duration) ([]string, error) {
	r, e := o.Load()
	if e != nil {
		return nil, e
	}
	if timeout <= 0 || r.Phase != state.PhaseExecCreated || r.ExecID != d.ExecID || r.RunID != d.RunID || r.DaemonID != d.Source.DaemonID || r.SourceContainerID != d.Source.ContainerID || r.SourceStartedAt != d.Source.StartedAt {
		return nil, docker.ErrQuarantine
	}
	client, e := docker.NewClient(socket)
	if e != nil {
		return nil, e
	}
	client.Close()
	r.Phase = state.PhaseExecStarted
	if e = o.Save(r); e != nil {
		return nil, e
	}
	return ExportArgs(socket, d, timeout), nil
}

// recoverSource is reached only after concrete Docker worker terminal proof.
func recoverSource(ctx context.Context, o *state.Owner, c *docker.Client, outcome state.Outcome, neverAuthorized bool) (docker.TerminalProof, error) {
	var proof docker.TerminalProof
	r, e := o.Load()
	if e != nil {
		return proof, e
	}
	block := func() (docker.TerminalProof, error) {
		r.Phase = state.PhaseQuarantine
		r.Status = state.StatusBlocked
		if e := o.Save(r); e != nil {
			return proof, e
		}
		return proof, docker.ErrQuarantine
	}
	if r.ExecID == "" || r.SourceContainerID == "" {
		return block()
	}
	s := docker.Source{DaemonID: r.DaemonID, ContainerID: r.SourceContainerID, StartedAt: r.SourceStartedAt}
	status, e := c.CheckSource(ctx, s)
	if e != nil {
		return block()
	}
	if status == docker.SourceTerminal {
		proof.SourceTerminal = true
	} else {
		p, e := c.PreparePostgres(ctx, s)
		if e != nil {
			return block()
		}
		d := docker.Dump{Source: s, ExecID: r.ExecID, RunID: r.RunID, Database: p.Database, User: p.User}
		if neverAuthorized {
			proof, e = c.VerifyUnstartedDump(ctx, d)
		} else {
			proof, e = c.CancelDump(ctx, d)
		}
		if e != nil {
			return block()
		}
	}
	if !proof.SourceTerminal && ((proof.ExecExitCode == nil && !proof.ExecNeverStarted) || !proof.NoProcesses || !proof.NoSessions) {
		return block()
	}
	if outcome == state.OutcomeSuccess && (proof.SourceTerminal || proof.ExecExitCode == nil || *proof.ExecExitCode != 0) {
		return block()
	}
	e = o.Release(r, state.TerminalProof{WorkerTerminal: true, SourceTerminal: true}, state.Result{RunID: r.RunID, Status: outcome})
	return proof, e
}
