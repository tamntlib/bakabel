package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
)

// Repository runs a pinned Restic executable. Env is supplied by the worker from
// credential files; neither it nor raw Restic diagnostics are included in errors.
type Repository struct {
	Binary string
	Env    []string
	// VerifySource is a fixed adapter postflight, not a user-configurable hook.
	// It runs before any complete tag is published.
	VerifySource func(context.Context) error `json:"-"`
}

// Smaller packs leave room for concurrent open-unlinked uploads in worker tmpfs.
// This is a measured default, not a universal temporary-storage bound.
const packSizeArg = "--pack-size=4"

type Snapshot struct {
	ID       string   `json:"id"`
	Tags     []string `json:"tags"`
	Paths    []string `json:"paths"`
	Hostname string   `json:"hostname"`
	Time     string   `json:"time"`
}

type Result struct {
	Status     string
	SnapshotID string
	Err        error
	// FailureStage is a fixed diagnostic code, populated only on error.
	FailureStage string
}

// cappedBuffer bounds machine-readable Restic output. It keeps consuming the
// pipe after reaching the bound, so a noisy child cannot deadlock its parent.
type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-b.buffer.Len() {
		b.overflow = true
		p = p[:b.limit-b.buffer.Len()]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

// CommandError exposes only a child exit code and a finite, heuristic reason.
// A stderr phrase is not proof of an OS errno or an OOM; raw stderr is not kept.
type CommandError struct {
	exitCode int
	reason   string
}

func (e *CommandError) Error() string  { return fmt.Sprintf("restic failed (exit %d)", e.exitCode) }
func (e *CommandError) ExitCode() int  { return e.exitCode }
func (e *CommandError) Reason() string { return e.reason }

func stderrReason(stderr []byte) string {
	text := bytes.ToLower(stderr)
	switch {
	case bytes.Contains(text, []byte("no space left on device")):
		return "enospc"
	case bytes.Contains(text, []byte("permission denied")), bytes.Contains(text, []byte("access denied")), bytes.Contains(text, []byte("accessdenied")):
		return "permission"
	case bytes.Contains(text, []byte("connection refused")), bytes.Contains(text, []byte("no such host")), bytes.Contains(text, []byte("connection reset")), bytes.Contains(text, []byte("service unavailable")):
		return "backend"
	default:
		return "unknown"
	}
}

func (r Repository) command(ctx context.Context, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, r.Binary, append([]string{"--no-cache"}, args...)...)
	cmd.Env = r.Env
	cmd.Stdout = out
	stderr := &cappedBuffer{limit: 64 * 1024}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return &CommandError{exitCode: exit.ExitCode(), reason: stderrReason(stderr.Bytes())}
		}
		return errors.New("cannot execute restic")
	}
	return nil
}

var errSnapshotResponse = errors.New("invalid restic snapshot response")

func (r Repository) Snapshots(ctx context.Context) ([]Snapshot, error) {
	out := &cappedBuffer{limit: 16 * 1024 * 1024}
	if err := r.command(ctx, out, "snapshots", "--json"); err != nil {
		return nil, err
	}
	if out.overflow {
		return nil, errors.New("snapshot listing exceeds safety bound")
	}
	var snapshots []Snapshot
	if err := json.Unmarshal(out.Bytes(), &snapshots); err != nil {
		return nil, errSnapshotResponse
	}
	return snapshots, nil
}

// Backup never marks a snapshot complete on producer, upload, listing or
// finalization error. The caller separately owns source-export cancellation.
func (r Repository) Backup(ctx context.Context, m Metadata, run, host string, sourceArgs []string) Result {
	result := Result{Status: "unknown"}
	fail := func(stage string, err error) Result {
		result.Err = err
		if err != nil && result.FailureStage == "" {
			if errors.Is(err, errSnapshotResponse) {
				stage = "metadata_readback"
			}
			result.FailureStage = stage
		}
		return result
	}
	tags, err := EncodeTags(m, "unknown", run)
	if err != nil {
		return fail("metadata_readback", err)
	}
	before, err := r.Snapshots(ctx)
	if err != nil {
		return fail("list_before", err)
	}
	for _, s := range before {
		if hasTag(s.Tags, "bakabel.run="+run) {
			return fail("metadata_readback", errors.New("run identity already exists"))
		}
	}
	args := []string{"backup", packSizeArg, "--json", "--host", host}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	args = append(args, sourceArgs...)
	backupErr := r.command(ctx, io.Discard, args...)
	if backupErr != nil {
		result.FailureStage = "backup"
	}
	all, err := r.Snapshots(ctx)
	if err != nil {
		return fail("list_after", errors.Join(backupErr, err))
	}
	var matches []Snapshot
	for _, s := range all {
		if hasTag(s.Tags, "bakabel.run="+run) {
			matches = append(matches, s)
		}
	}
	if len(matches) != 1 {
		return fail("metadata_readback", errors.Join(backupErr, errors.New("backup did not produce exactly one owned snapshot")))
	}
	snapshot := matches[0]
	result.SnapshotID = snapshot.ID
	got, status, gotRun, err := DecodeTags(snapshot.Tags)
	if err != nil || gotRun != run || status != "unknown" || !reflect.DeepEqual(got, m) || !reflect.DeepEqual(snapshot.Paths, m.Paths) || snapshot.Hostname != host || !validSnapshotID(snapshot.ID) {
		return fail("metadata_readback", errors.Join(backupErr, errors.New("snapshot metadata readback mismatch")))
	}
	if backupErr == nil && r.VerifySource != nil {
		if err = r.VerifySource(ctx); err != nil {
			return fail("source_verification", errors.New("source verification failed"))
		}
	}
	status = "complete"
	if backupErr != nil {
		status = "partial"
	}
	if err = r.command(ctx, io.Discard, "tag", "--remove", "bakabel.status=unknown", "--add", "bakabel.status="+status, snapshot.ID); err != nil {
		return fail("tag", errors.Join(backupErr, err))
	}
	all, err = r.Snapshots(ctx)
	if err != nil {
		return fail("final_readback", errors.Join(backupErr, err))
	}
	matches = nil
	for _, s := range all {
		if hasTag(s.Tags, "bakabel.run="+run) {
			matches = append(matches, s)
		}
	}
	if len(matches) != 1 {
		return fail("metadata_readback", errors.Join(backupErr, errors.New("ambiguous final snapshot identity")))
	}
	got, gotStatus, gotRun, err := DecodeTags(matches[0].Tags)
	if err != nil || gotStatus != status || gotRun != run || !reflect.DeepEqual(got, m) || !reflect.DeepEqual(matches[0].Paths, m.Paths) || matches[0].Hostname != host || !validSnapshotID(matches[0].ID) {
		return fail("metadata_readback", errors.Join(backupErr, errors.New("final snapshot metadata readback mismatch")))
	}
	result.SnapshotID = matches[0].ID
	result.Status = status
	result.Err = backupErr
	return result
}

func (r Repository) Dump(ctx context.Context, id, path string, out io.Writer) error {
	if !validSnapshotID(id) {
		return errors.New("exact snapshot ID required")
	}
	return r.command(ctx, out, "dump", id, path)
}
func validSnapshotID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
