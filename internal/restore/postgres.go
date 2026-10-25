// Package restore implements repository-only recovery without scheduler/source state.
package restore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"sort"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

type PostgresResult struct {
	Status         string
	SnapshotID     string
	Exec           docker.RestoreExec
	ImportExitCode *int
	Terminal       docker.TerminalProof
}

// PersistExec must fsync the checkpoint into the owning worker run before it
// returns. Keep it until Terminal proves the target import/backend stopped. No
// default in-memory callback is supplied: production must not lose ownership on
// worker SIGKILL. A test can explicitly supply its own disposable callback.
type RestoreOptions struct {
	PersistExec func(docker.RestoreExec) error
	// BeforeCreate persists ambiguous-create intent only after all read-only
	// preflight has succeeded, immediately before the Engine create request.
	BeforeCreate func() error
}

// DatabasePolicyMatches compares normalized role-name grants independently of
// repository JSON order or the target cluster's SQL ordering.
func DatabasePolicyMatches(want backup.PostgresMetadata, got docker.PostgresMetadata) bool {
	if want.Owner != got.Owner {
		return false
	}
	grants := append([]backup.Grant{}, want.ACL...)
	actual := make([]backup.Grant, 0, len(got.ACL))
	for _, g := range got.ACL {
		actual = append(actual, backup.Grant{Grantor: g.Grantor, Grantee: g.Grantee, Privilege: g.Privilege, Grantable: g.Grantable})
	}
	less := func(a, b backup.Grant) bool {
		if a.Grantor != b.Grantor {
			return a.Grantor < b.Grantor
		}
		if a.Grantee != b.Grantee {
			return a.Grantee < b.Grantee
		}
		if a.Privilege != b.Privilege {
			return a.Privilege < b.Privilege
		}
		return !a.Grantable && b.Grantable
	}
	sort.Slice(grants, func(i, j int) bool { return less(grants[i], grants[j]) })
	sort.Slice(actual, func(i, j int) bool { return less(actual[i], actual[j]) })
	return reflect.DeepEqual(grants, actual)
}

// RestorePostgres restores one trusted complete custom-format dump. It does NOT
// provide application verification, concurrent-DDL isolation, automatic role or
// extension provisioning, rollback/drop on failure, or traffic switching.
func RestorePostgres(ctx context.Context, repo backup.Repository, snapshot backup.Snapshot, client *docker.Client, target docker.Source, literalDatabase, user string, options ...RestoreOptions) (PostgresResult, error) {
	result := PostgresResult{Status: "failed", SnapshotID: snapshot.ID}
	m, err := snapshot.Restorable()
	if err != nil {
		return result, err
	}
	if m.Kind != "postgres" || m.Postgres == nil || len(m.Paths) != 1 || m.Postgres.ServerVersion != docker.RestorePostgresVersion || m.Postgres.ClientVersion != docker.RestorePostgresVersion {
		return result, errors.New("restore requires supported stock PG18 custom-format metadata and one dump path")
	}
	if client == nil || len(options) != 1 || options[0].PersistExec == nil {
		return result, errors.New("restore requires target client and durable exec checkpoint callback")
	}
	// Do not accept an invented handoff paired with a real archive ID. Bind the
	// metadata/layout/status to a repository readback of the exact chosen snapshot.
	all, err := repo.Snapshots(ctx)
	if err != nil {
		return result, err
	}
	matches := 0
	for _, s := range all {
		if s.ID == snapshot.ID {
			matches++
			actual, e := s.Restorable()
			if e != nil || !reflect.DeepEqual(actual, m) {
				return result, errors.New("repository snapshot metadata/readback mismatch")
			}
		}
	}
	if matches != 1 {
		return result, errors.New("exact snapshot not uniquely present in repository")
	}
	p, err := client.PrepareRestorePostgres(ctx, target, literalDatabase, user)
	if err != nil {
		return result, err
	}
	if p.Metadata.ClusterID == m.Postgres.ClusterID && p.Metadata.DatabaseOID == m.Postgres.DatabaseOID {
		return result, errors.New("target is source database (physical fingerprint), including aliases/empty source")
	}
	if !DatabasePolicyMatches(*m.Postgres, p.Metadata) {
		return result, errors.New("operator must prepare exact database owner and normalized ACL before restore")
	}
	if err = client.CheckRestoreEmpty(ctx, p); err != nil {
		return result, err
	}
	var random [24]byte
	if _, err = rand.Read(random[:]); err != nil {
		return result, errors.New("restore token unavailable")
	}
	result.Exec, err = client.CreateRestoreExec(ctx, p, "restore_"+hex.EncodeToString(random[:]), options[0].PersistExec, options[0].BeforeCreate)
	if err != nil {
		if result.Exec.ExecID != "" {
			clean, done := context.WithTimeout(context.Background(), 15*time.Second)
			var proofErr error
			result.Terminal, proofErr = client.VerifyUnstartedRestoreExec(clean, result.Exec)
			done()
			return result, errors.Join(err, proofErr)
		}
		return result, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe() // synchronous backpressure, no dump staging or accumulation
	readerDone := make(chan error, 1)
	go func() {
		e := repo.Dump(streamCtx, snapshot.ID, m.Paths[0], writer)
		writer.CloseWithError(e)
		readerDone <- e
	}()
	code, importErr := client.StreamRestoreExec(streamCtx, result.Exec, reader)
	if importErr != nil {
		cancel()
	}
	reader.Close()
	readerErr := <-readerDone
	// An independent bounded cleanup context survives caller cancellation. If it
	// fails, the caller MUST keep the checkpoint/quarantine for later recovery.
	clean, done := context.WithTimeout(context.Background(), 15*time.Second)
	if errors.Is(importErr, docker.ErrRestoreNotStarted) {
		result.Terminal, err = client.VerifyUnstartedRestoreExec(clean, result.Exec)
	} else {
		result.Terminal, err = client.CancelRestoreExec(clean, result.Exec)
	}
	done()
	result.ImportExitCode = result.Terminal.ExecExitCode
	if importErr != nil || readerErr != nil || err != nil || code != 0 || ctx.Err() != nil {
		return result, errors.Join(importErr, readerErr, err, ctx.Err())
	}
	if result.ImportExitCode == nil || *result.ImportExitCode != 0 || !result.Terminal.NoProcesses || !result.Terminal.NoSessions {
		return result, errors.New("target import terminal success unverified")
	}
	post, err := client.ReadRestoreMetadata(ctx, p)
	if err != nil {
		return result, err
	}
	if post.ClusterID != p.Metadata.ClusterID || post.DatabaseOID != p.Metadata.DatabaseOID || !DatabasePolicyMatches(*m.Postgres, post) {
		return result, errors.New("post-import target identity/database owner/ACL policy mismatch")
	}
	result.Status = "restored"
	return result, nil
}
