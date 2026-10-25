package app

import (
	"context"
	"errors"
	"flag"
	"io"

	"strings"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/config"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	pgrestore "github.com/tamntlib/bakabel/internal/restore"
	"github.com/tamntlib/bakabel/internal/state"
)

type RestoreRequest struct {
	SnapshotID        string `json:"snapshotID"`
	PostgresContainer string `json:"postgresContainer,omitempty"`
	Database          string `json:"database,omitempty"`
	User              string `json:"user,omitempty"`
	Directory         string `json:"directory,omitempty"`
	Volume            string `json:"volume,omitempty"`
}

func parseRestore(args []string) (RestoreRequest, error) {
	var req RestoreRequest
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&req.SnapshotID, "snapshot", "", "")
	fs.StringVar(&req.PostgresContainer, "postgres-container", "", "")
	fs.StringVar(&req.Database, "database", "", "")
	fs.StringVar(&req.User, "user", "", "")
	fs.StringVar(&req.Directory, "directory", "", "")
	fs.StringVar(&req.Volume, "volume", "", "")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return req, errors.New("invalid restore arguments")
	}
	if len(req.SnapshotID) != 64 || strings.Trim(req.SnapshotID, "0123456789abcdef") != "" {
		return req, errors.New("exact snapshot ID required")
	}
	pg := req.PostgresContainer != ""
	file := req.Directory != ""
	volume := req.Volume != ""
	count := 0
	for _, v := range []bool{pg, file, volume} {
		if v {
			count++
		}
	}
	if count != 1 || pg && (req.Database == "" || req.User == "") || !pg && (req.Database != "" || req.User != "") {
		return req, errors.New("explicit single restore target required")
	}
	return req, nil
}

func exactSnapshot(ctx context.Context, repo backup.Repository, id string) (backup.Snapshot, error) {
	all, e := repo.Snapshots(ctx)
	if e != nil {
		return backup.Snapshot{}, e
	}
	var result backup.Snapshot
	matches := 0
	for _, s := range all {
		if s.ID == id {
			if _, e = s.Restorable(); e != nil {
				return s, e
			}
			result = s
			matches++
		}
	}
	if matches != 1 {
		return result, errors.New("complete exact snapshot not uniquely present")
	}
	return result, nil
}

// Restore needs repository access and an explicit NEW target, not discovery or
// previous source/state history. The configured state mount is a fresh mutex.
func Restore(ctx context.Context, c config.Config, req RestoreRequest) (WorkflowResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var result WorkflowResult
	client, e := workflowClient(c)
	if e != nil {
		return result, e
	}
	defer client.Close()
	s, e := exactSnapshot(ctx, configuredRepository(c), req.SnapshotID)
	if e != nil {
		return result, e
	}
	m, e := s.Restorable()
	if e != nil {
		return result, e
	}
	plan, _, e := runtimePlan(ctx, c, client)
	if e != nil {
		return result, e
	}
	if m.Kind == "volume" {
		if req.PostgresContainer != "" || req.Directory == "" && req.Volume == "" {
			return result, errors.New("explicit file restore target required")
		}
		if req.Volume != "" {
			v, err := client.InspectLocalVolume(ctx, req.Volume)
			if err != nil {
				return result, err
			}
			req.Directory = v.Mountpoint
		}
		if !nativePath(req.Directory) {
			return result, errors.New("native absolute directory required")
		}
		info, err := client.Info(ctx)
		if err != nil {
			return result, err
		}
		t := docker.Target{ID: m.Source, Kind: "volume", Source: docker.Source{DaemonID: info.ID}}
		h, err := startWorkflow(ctx, c, client, plan, []docker.Target{t}, req)
		return reconcileWorkflowLaunch(ctx, c, h, err)
	}
	if m.Kind != "postgres" || req.PostgresContainer == "" {
		return result, errors.New("snapshot/target type mismatch")
	}
	target, e := client.CaptureSource(ctx, req.PostgresContainer)
	if e != nil {
		return result, e
	}
	// Read-only prerequisite check before owning/spawning anything. Worker repeats
	// all checks; drift or a create/persist interruption remains quarantined.
	p, e := client.PrepareRestorePostgres(ctx, target, req.Database, req.User)
	if e != nil {
		return result, e
	}
	if m.Postgres == nil || m.Postgres.ClusterID == p.Metadata.ClusterID && m.Postgres.DatabaseOID == p.Metadata.DatabaseOID {
		return result, errors.New("restore target is source database identity")
	}
	if !pgrestore.DatabasePolicyMatches(*m.Postgres, p.Metadata) {
		return result, errors.New("operator must prepare database owner/ACL before restore")
	}
	if e = client.CheckRestoreEmpty(ctx, p); e != nil {
		return result, e
	}
	t := docker.Target{ID: m.Source, Kind: "postgres", Source: target, Database: req.Database}
	h, e := startWorkflow(ctx, c, client, plan, []docker.Target{t}, req)
	return reconcileWorkflowLaunch(ctx, c, h, e)
}

func restorePostgresTarget(ctx context.Context, o *state.Owner, c *docker.Client, repo backup.Repository, j workflowJob, t docker.Target) TargetResult {
	tr := TargetResult{TargetID: t.ID, Status: "unknown", SnapshotID: j.Restore.SnapshotID, Error: "restore failed"}
	s, e := exactSnapshot(ctx, repo, j.Restore.SnapshotID)
	if e != nil {
		return tr
	}
	r, e := o.Load()
	if e != nil {
		return tr
	}
	createBoundary := false
	res, e := pgrestore.RestorePostgres(ctx, repo, s, c, t.Source, j.Restore.Database, j.Restore.User, pgrestore.RestoreOptions{BeforeCreate: func() error {
		current, err := o.Load()
		if err != nil || current.RunID != j.RunID || current.Phase != state.PhaseIntent || current.SourceContainerID != "" {
			return docker.ErrQuarantine
		}
		r = current
		r.TargetID = targetHash(t.ID)
		r.SourceContainerID = t.Source.ContainerID
		r.SourceStartedAt = t.Source.StartedAt
		r.ExecKind = "restore"
		r.Phase = state.PhaseCreatingExec
		createBoundary = true
		return o.Save(r)
	}, PersistExec: func(d docker.RestoreExec) error {
		r.ImportRunID = d.RunID
		r.ExecID = d.ExecID
		r.Phase = state.PhaseExecCreated
		if err := o.Save(r); err != nil {
			return err
		}
		r.Phase = state.PhaseExecStarted
		return o.Save(r)
	}})
	if !createBoundary {
		// No import-create side effect was attempted. Do not turn an ordinary
		// repository/version/catalog preflight failure into a durable create gap.
		return tr
	}
	if res.Exec.ExecID == "" || !dumpTerminal(res.Terminal) {
		quarantine(o)
		return tr
	}
	r, le := o.Load()
	if le != nil {
		return tr
	}
	if _, le = o.AdvanceExport(r, state.TerminalProof{SourceTerminal: true}); le != nil {
		return tr
	}
	if e == nil && res.Status == "restored" {
		tr.Status = "restored"
		tr.Error = ""
	}
	return tr
}
