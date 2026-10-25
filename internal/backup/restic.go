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
}

// cappedBuffer bounds machine-readable Restic output. It keeps consuming the
// pipe after reaching the bound, so a noisy child cannot deadlock its parent.
type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n > b.limit-b.Len() {
		b.overflow = true
		p = p[:b.limit-b.Len()]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func (r Repository) command(ctx context.Context, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, r.Binary, append([]string{"--no-cache"}, args...)...)
	cmd.Env = r.Env
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("restic failed (exit %d)", exit.ExitCode())
		}
		return errors.New("cannot execute restic")
	}
	return nil
}

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
		return nil, errors.New("invalid restic snapshot response")
	}
	return snapshots, nil
}

// Backup never marks a snapshot complete on producer, upload, listing or
// finalization error. The caller separately owns source-export cancellation.
func (r Repository) Backup(ctx context.Context, m Metadata, run, host string, sourceArgs []string) Result {
	result := Result{Status: "unknown"}
	tags, err := EncodeTags(m, "unknown", run)
	if err != nil {
		result.Err = err
		return result
	}
	before, err := r.Snapshots(ctx)
	if err != nil {
		result.Err = err
		return result
	}
	for _, s := range before {
		if hasTag(s.Tags, "bakabel.run="+run) {
			result.Err = errors.New("run identity already exists")
			return result
		}
	}
	args := []string{"backup", "--json", "--host", host}
	for _, tag := range tags {
		args = append(args, "--tag", tag)
	}
	args = append(args, sourceArgs...)
	backupErr := r.command(ctx, io.Discard, args...)
	all, err := r.Snapshots(ctx)
	if err != nil {
		result.Err = errors.Join(backupErr, err)
		return result
	}
	var matches []Snapshot
	for _, s := range all {
		if hasTag(s.Tags, "bakabel.run="+run) {
			matches = append(matches, s)
		}
	}
	if len(matches) != 1 {
		result.Err = errors.Join(backupErr, errors.New("backup did not produce exactly one owned snapshot"))
		return result
	}
	snapshot := matches[0]
	result.SnapshotID = snapshot.ID
	got, status, gotRun, err := DecodeTags(snapshot.Tags)
	if err != nil || gotRun != run || status != "unknown" || !reflect.DeepEqual(got, m) || !reflect.DeepEqual(snapshot.Paths, m.Paths) || snapshot.Hostname != host || !validSnapshotID(snapshot.ID) {
		result.Err = errors.Join(backupErr, errors.New("snapshot metadata readback mismatch"))
		return result
	}
	if backupErr == nil && r.VerifySource != nil {
		if err = r.VerifySource(ctx); err != nil {
			result.Err = errors.New("source verification failed")
			return result
		}
	}
	status = "complete"
	if backupErr != nil {
		status = "partial"
	}
	if err = r.command(ctx, io.Discard, "tag", "--remove", "bakabel.status=unknown", "--add", "bakabel.status="+status, snapshot.ID); err != nil {
		result.Err = errors.Join(backupErr, err)
		return result
	}
	all, err = r.Snapshots(ctx)
	if err != nil {
		result.Err = errors.Join(backupErr, err)
		return result
	}
	matches = nil
	for _, s := range all {
		if hasTag(s.Tags, "bakabel.run="+run) {
			matches = append(matches, s)
		}
	}
	if len(matches) != 1 {
		result.Err = errors.Join(backupErr, errors.New("ambiguous final snapshot identity"))
		return result
	}
	got, gotStatus, gotRun, err := DecodeTags(matches[0].Tags)
	if err != nil || gotStatus != status || gotRun != run || !reflect.DeepEqual(got, m) || !reflect.DeepEqual(matches[0].Paths, m.Paths) || matches[0].Hostname != host || !validSnapshotID(matches[0].ID) {
		result.Err = errors.Join(backupErr, errors.New("final snapshot metadata readback mismatch"))
		return result
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
