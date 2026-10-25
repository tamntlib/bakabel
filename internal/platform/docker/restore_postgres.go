package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The trusted catalog baseline is supported only for this stock PG18 revision.
const RestorePostgresVersion = 180006

func (c *Client) restoreSQL(ctx context.Context, p Postgres, q string) ([]byte, error) {
	conn, e := restoreConninfo(p.Database, p.User)
	if e != nil {
		return nil, e
	}
	return c.control(ctx, p.Source, []string{"/usr/local/bin/psql", "-XAt", "--no-password", "--set", "ON_ERROR_STOP=1", "--dbname", conn, "--command", q})
}

func (c *Client) ReadRestoreMetadata(ctx context.Context, p RestorePostgresTarget) (PostgresMetadata, error) {
	var m PostgresMetadata
	if !p.prepared {
		return m, ErrQuarantine
	}
	raw, e := c.restoreSQL(ctx, p.postgres, metadataSQL)
	if e != nil {
		return m, errors.New("cannot verify target PostgreSQL identity/owner/ACL")
	}
	if json.Unmarshal(raw, &m) != nil || !m.Superuser || m.Database != p.postgres.Database || m.ClusterID == "" || m.DatabaseOID == "" || m.Owner == "" || m.ACL == nil || m.ServerVersion != RestorePostgresVersion || m.Format != "custom" {
		return m, errors.New("unsupported target PostgreSQL identity/version/permissions")
	}
	if _, e = strconv.ParseUint(m.ClusterID, 10, 64); e != nil {
		return m, ErrQuarantine
	}
	if _, e = strconv.ParseUint(m.DatabaseOID, 10, 32); e != nil {
		return m, ErrQuarantine
	}
	m.ClientVersion = p.Metadata.ClientVersion
	return m, nil
}

// PrepareRestorePostgres requires the fixed local Unix-socket superuser policy
// already used by B1. No role/ACL/authentication changes are made automatically.
func (c *Client) PrepareRestorePostgres(ctx context.Context, s Source, database, user string) (RestorePostgresTarget, error) {
	p := RestorePostgresTarget{postgres: Postgres{Source: s, Database: database, User: user}, prepared: true}
	if _, e := restoreConninfo(database, user); e != nil {
		return RestorePostgresTarget{}, e
	}
	for _, tool := range []string{"pg_restore", "psql"} {
		raw, e := c.control(ctx, s, []string{"/usr/local/bin/" + tool, "--version"})
		if e != nil {
			return RestorePostgresTarget{}, errors.New("target PostgreSQL client version unavailable")
		}
		if strings.TrimSpace(string(raw)) != fmt.Sprintf("%s (PostgreSQL) 18.6", tool) {
			return RestorePostgresTarget{}, errors.New("unsupported target PostgreSQL client version")
		}
	}
	p.Metadata.ClientVersion = RestorePostgresVersion
	m, e := c.ReadRestoreMetadata(ctx, p)
	if e != nil {
		return RestorePostgresTarget{}, e
	}
	p.Metadata = m
	return p, nil
}

func (c *Client) CheckRestoreEmpty(ctx context.Context, p RestorePostgresTarget) error {
	if !p.prepared {
		return ErrQuarantine
	}
	raw, e := c.restoreSQL(ctx, p.postgres, restoreInventorySQL)
	if e != nil {
		return errors.New("cannot verify complete target catalog inventory")
	}
	return checkRestoreInventory(raw)
}

// RestorePostgresTarget fixes the endpoint and literal database. Only preparation
// can mint a usable value. The operator must exclude other writers/DDL throughout.
type RestorePostgresTarget struct {
	postgres Postgres
	prepared bool
	Metadata PostgresMetadata
}

func restoreConninfo(database, user string) (string, error) {
	return (Postgres{Database: database, User: user}).conninfo()
}

// RestoreExec is a secret-free recovery checkpoint. Persist it BEFORE starting.
// Target is the destination (not the lost database source). Its exact daemon,
// immutable container ID, incarnation, exec ID and token are recovery authority.
type RestoreExec struct {
	Target                        Source
	ExecID, RunID, Database, User string
}

func (c *Client) CreateRestoreExec(ctx context.Context, p RestorePostgresTarget, run string, persist func(RestoreExec) error, beforeCreate ...func() error) (RestoreExec, error) {
	d := RestoreExec{Target: p.postgres.Source, RunID: run, Database: p.postgres.Database, User: p.postgres.User}
	if !p.prepared || !validToken(run) || persist == nil || len(beforeCreate) > 1 {
		return d, ErrQuarantine
	}
	conn, e := restoreConninfo(d.Database, d.User)
	if e != nil {
		return d, e
	}
	status, e := c.CheckSource(ctx, d.Target)
	if e != nil || status != SourceRunning {
		return d, ErrQuarantine
	}
	cfg := ExecConfig{User: "0", Cmd: []string{"/usr/local/bin/pg_restore", "--no-password", "--exit-on-error", "--dbname", conn}, Env: pgEnv(run), AttachStdin: true, AttachStdout: true, AttachStderr: true}
	var out struct {
		ID string `json:"Id"`
	}
	// This is the exact side-effect boundary, after all read-only validation.
	// Only trusted internal ownership bookkeeping may run here.
	if len(beforeCreate) == 1 && beforeCreate[0] != nil {
		if e = beforeCreate[0](); e != nil {
			return d, e
		}
	}
	if e = c.request(ctx, "POST", "/containers/"+d.Target.ContainerID+"/exec", cfg, &out); e != nil {
		return d, e
	}
	if !validID(out.ID) {
		return d, ErrQuarantine
	}
	d.ExecID = out.ID
	if e = persist(d); e != nil {
		return d, errors.New("persist restore exec checkpoint failed")
	}
	return d, nil
}
