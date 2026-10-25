package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

const workerSocket = "/run/bakabel/docker.sock"
const workerJobFile = "/run/bakabel/job.json"
const workerResultDir = "/run/bakabel/output"
const workerPassword = "/run/secrets/restic-password"

// WorkerLaunch is the minimal B1 single-source, local repository handoff. Paths
// must refer to trusted, explicit files/directories on the SAME daemon node.
// No discovery, secret copying, Swarm inheritance or repository init is implied.
type WorkerLaunch struct {
	Image, Socket, JobDir, RepositoryDir, PasswordFile string
	Timeout                                            time.Duration
}
type workerJob struct {
	Version  int             `json:"version"`
	Dump     docker.Dump     `json:"dump"`
	Metadata backup.Metadata `json:"metadata"`
	Timeout  time.Duration   `json:"timeout"`
}
type WorkerResult struct {
	RunID      string `json:"runID"`
	Status     string `json:"status"`
	SnapshotID string `json:"snapshotID,omitempty"`
	Error      string `json:"error,omitempty"`
}

// publishJSON is a bounded, private, atomic, no-replace publication in a trusted
// run directory. Sync both data and directory before any dependent Docker call.
func publishJSON(dir, name string, v any, limit int) error {
	b, e := json.Marshal(v)
	if e != nil || len(b) > limit {
		return errors.New("invalid worker record")
	}
	f, e := os.CreateTemp(dir, ".record-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Link(f.Name(), filepath.Join(dir, name)); e != nil {
		return e
	}
	if e = os.Remove(f.Name()); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func readJSON(path string, v any, limit int) error {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > int64(limit) {
		return errors.New("invalid worker record")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(b) > limit {
		return errors.New("invalid worker record")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return errors.New("invalid worker record")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid worker record")
	}
	return nil
}
func readWorkerResult(path string) (WorkerResult, error) {
	var r WorkerResult
	if e := readJSON(path, &r, 1024); e != nil {
		return r, e
	}
	if len(r.RunID) != 32 {
		return r, errors.New("invalid worker receipt")
	}
	b, e := hex.DecodeString(r.RunID)
	if e != nil || hex.EncodeToString(b) != r.RunID {
		return r, errors.New("invalid worker receipt")
	}
	if r.Error != "" && r.Error != "backup failed" {
		return r, errors.New("invalid worker receipt")
	}
	if r.Status != "complete" && r.Status != "partial" && r.Status != "unknown" {
		return r, errors.New("invalid worker receipt")
	}
	if r.SnapshotID != "" {
		b, e = hex.DecodeString(r.SnapshotID)
		if e != nil || len(b) != 32 || hex.EncodeToString(b) != r.SnapshotID {
			return r, errors.New("invalid worker receipt")
		}
	}
	if r.Status == "complete" && (r.SnapshotID == "" || r.Error != "") {
		return r, errors.New("invalid worker receipt")
	}
	return r, nil
}
func postgresMetadata(p docker.Postgres) backup.Metadata {
	m := p.Metadata
	acl := make([]backup.Grant, 0, len(m.ACL))
	for _, g := range m.ACL {
		acl = append(acl, backup.Grant{Grantor: g.Grantor, Grantee: g.Grantee, Privilege: g.Privilege, Grantable: g.Grantable})
	}
	return backup.Metadata{Version: 1, Kind: "postgres", Source: "b1/postgres", Paths: []string{"/postgres.dump"}, Postgres: &backup.PostgresMetadata{Database: m.Database, ClusterID: m.ClusterID, DatabaseOID: m.DatabaseOID, ServerVersion: m.ServerVersion, ClientVersion: m.ClientVersion, Format: m.Format, Owner: m.Owner, ACL: acl}}
}
func quarantine(o *state.Owner) error {
	r, e := o.Load()
	if e != nil {
		return e
	}
	r.Phase = state.PhaseQuarantine
	r.Status = state.StatusBlocked
	if e = o.Save(r); e != nil {
		return e
	}
	return docker.ErrQuarantine
}
func recordWorker(r state.Record) docker.Worker {
	return docker.Worker{DaemonID: r.DaemonID, ContainerID: r.WorkerContainerID, Name: r.WorkerName, RunID: r.RunID}
}

// LaunchPostgresWorker holds the supplied Owner guard throughout. Source exec
// ID, job, exact worker ID and start authorization are durable BEFORE start.
// Any uncertain side effect retains owner.json; no retry/spawn on error.
func LaunchPostgresWorker(ctx context.Context, o *state.Owner, c *docker.Client, p docker.Postgres, l WorkerLaunch) (docker.Worker, error) {
	var w docker.Worker
	if l.Timeout <= 0 || l.Timeout > 24*time.Hour || l.Image == "" {
		return w, errors.New("invalid worker launch")
	}
	for _, path := range []string{l.Socket, l.JobDir, l.RepositoryDir, l.PasswordFile} {
		if !filepath.IsAbs(path) {
			return w, errors.New("absolute worker mounts required")
		}
	}
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return w, e
	}
	run := hex.EncodeToString(random[:])
	w = docker.Worker{DaemonID: p.Source.DaemonID, Name: "bakabel-worker-" + run, RunID: run}
	d, e := Prepare(ctx, o, c, p, run, w.Name)
	if e != nil {
		return w, e
	}
	fail := func() (docker.Worker, error) { return w, quarantine(o) }
	if e = os.Mkdir(filepath.Join(l.JobDir, "output"), 0700); e != nil {
		return fail()
	}
	if e = publishJSON(l.JobDir, "job.json", workerJob{Version: 1, Dump: d, Metadata: postgresMetadata(p), Timeout: l.Timeout}, 16384); e != nil {
		return fail()
	}
	spec := docker.WorkerSpec{Image: l.Image, Mounts: []docker.WorkerMount{
		{Source: filepath.Join(l.JobDir, "job.json"), Target: workerJobFile, ReadOnly: true},
		{Source: filepath.Join(l.JobDir, "output"), Target: workerResultDir},
		{Source: l.RepositoryDir, Target: "/repository"},
		{Source: l.PasswordFile, Target: workerPassword, ReadOnly: true},
		{Source: l.Socket, Target: workerSocket, ReadOnly: true},
	}}
	w, e = c.CreateWorker(ctx, w, spec)
	if e != nil {
		return fail()
	}
	r, e := o.Load()
	if e != nil {
		return w, e
	}
	r.WorkerContainerID = w.ContainerID
	if e = o.Save(r); e != nil {
		return w, e
	}
	if _, e = Authorize(o, workerSocket, d, l.Timeout); e != nil {
		return fail()
	}
	r, e = o.Load()
	if e != nil {
		return w, e
	}
	r.WorkerStartAuthorized = true
	if e = o.Save(r); e != nil {
		return w, e
	}
	if e = c.StartWorker(ctx, w); e != nil {
		return fail()
	}
	return w, nil
}

// runWorker runs only the compiled fixed PG export pipeline. Nothing in the job
// chooses commands, binary paths, credential contents or environment keys.
func runWorker(ctx context.Context) int {
	var j workerJob
	if readJSON(workerJobFile, &j, 16384) != nil || j.Version != 1 || j.Timeout <= 0 || j.Timeout > 24*time.Hour || j.Dump.RunID == "" {
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, j.Timeout)
	defer cancel()
	repo := backup.Repository{Binary: "/usr/bin/restic", Env: []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "TMPDIR=/tmp", "GOMAXPROCS=2", "RESTIC_REPOSITORY=/repository", "RESTIC_PASSWORD_FILE=" + workerPassword}}
	args := []string{"--stdin-from-command", "--stdin-filename", "postgres.dump", "--", "/usr/local/bin/bakabel"}
	args = append(args, ExportArgs(workerSocket, j.Dump, j.Timeout)...)
	result := repo.Backup(ctx, j.Metadata, j.Dump.RunID, "b1-installation", args)
	receipt := WorkerResult{RunID: j.Dump.RunID, Status: result.Status, SnapshotID: result.SnapshotID}
	code := 0
	if result.Err != nil || result.Status != "complete" {
		receipt.Error = "backup failed"
		code = 1
	}
	if publishJSON(workerResultDir, "result.json", receipt, 1024) != nil {
		return 1
	}
	return code
}

// Recover has no caller proof callback. It verifies the exact Docker worker,
// kills only that verified worker if live, reads terminal state back, then calls
// source recovery. Missing/ambiguous identity never releases the owner guard.
func Recover(ctx context.Context, o *state.Owner, c *docker.Client, outcome state.Outcome) (docker.TerminalProof, error) {
	r, e := o.Load()
	if e != nil {
		return docker.TerminalProof{}, e
	}
	wp, e := c.InspectWorker(ctx, recordWorker(r))
	if e != nil {
		return docker.TerminalProof{}, quarantine(o)
	}
	// Recover a create response loss by concrete labels+random name; retain the
	// adopted exact ID before any destructive operation. Quarantine remains sticky.
	if r.WorkerContainerID == "" {
		r.WorkerContainerID = wp.Worker.ContainerID
		if e = o.Save(r); e != nil {
			return docker.TerminalProof{}, e
		}
	}
	neverRan := wp.Created
	if wp.Created {
		wp, e = c.DiscardCreatedWorker(ctx, wp.Worker)
	} else {
		wp, e = c.TerminateWorker(ctx, wp.Worker)
	}
	if e != nil || !wp.Terminal {
		return docker.TerminalProof{}, quarantine(o)
	}
	if outcome == state.OutcomeSuccess && wp.ExitCode != 0 {
		return docker.TerminalProof{}, quarantine(o)
	}
	return recoverSource(ctx, o, c, outcome, neverRan || !r.WorkerStartAuthorized)
}

// FinishWorker waits within ctx. Expiry uses a fresh bounded cleanup context:
// container KILL/readback before source cancellation; uncertain cleanup blocks.
func FinishWorker(ctx context.Context, o *state.Owner, c *docker.Client, jobDir string) (WorkerResult, docker.TerminalProof, error) {
	var result WorkerResult
	var proof docker.TerminalProof
	r, e := o.Load()
	if e != nil {
		return result, proof, e
	}
	var wp docker.WorkerProof
	for {
		wp, e = c.InspectWorker(ctx, recordWorker(r))
		if e != nil || wp.Terminal {
			break
		}
		select {
		case <-ctx.Done():
			e = ctx.Err()
		case <-time.After(100 * time.Millisecond):
			continue
		}
		break
	}
	waitErr := e
	outcome := state.OutcomeCanceled
	if wp.Terminal {
		result, e = readWorkerResult(filepath.Join(jobDir, "output", "result.json"))
		if e == nil && result.RunID == r.RunID && wp.ExitCode == 0 && result.Status == "complete" {
			outcome = state.OutcomeSuccess
		}
	}
	clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	proof, e = Recover(clean, o, c, outcome)
	if e != nil {
		return result, proof, e
	}
	if outcome != state.OutcomeSuccess {
		return result, proof, errors.New("worker backup failed")
	}
	return result, proof, waitErr
}
