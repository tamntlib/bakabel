package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrDumpFailed = errors.New("PostgreSQL export failed")

type Grant struct {
	Grantee, Grantor, Privilege string
	Grantable                   bool
}
type PostgresMetadata struct {
	Database      string  `json:"database"`
	DatabaseOID   string  `json:"database_oid"`
	ClusterID     string  `json:"cluster_id"`
	Owner         string  `json:"owner"`
	ACL           []Grant `json:"acl"`
	ServerVersion int     `json:"server_version"`
	ClientVersion int     `json:"client_version"`
	Format        string  `json:"format"`
	Superuser     bool    `json:"superuser"`
}
type Postgres struct {
	Source         Source
	Database, User string
	Metadata       PostgresMetadata
	prepared       bool
}

func (p Postgres) conninfo() (string, error) {
	quote := func(s string) string { return "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(s) + "'" }
	for _, s := range []string{p.Database, p.User} {
		if s == "" || len(s) > 256 || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
			return "", errors.New("invalid PostgreSQL database/user")
		}
	}
	return "host='/var/run/postgresql' port='5432' user=" + quote(p.User) + " dbname=" + quote(p.Database), nil
}
func pgEnv(token string) []string {
	return []string{"PGAPPNAME=" + token, "BAKABEL_RUN_ID=" + token, "PGHOSTADDR=", "PGPASSWORD=", "PGPASSFILE=/dev/null", "PGSERVICEFILE=/dev/null", "PGOPTIONS=", "PGCONNECT_TIMEOUT=10"}
}

// ACL NULL uses acldefault, including PUBLIC. Role names, not cluster-local OIDs,
// are the restore prerequisite contract. Sorting makes the representation stable.
const metadataSQL = `SELECT json_build_object(
 'database',d.datname,'database_oid',d.oid::text,
 'cluster_id',(pg_control_system()).system_identifier::text,
 'owner',pg_get_userbyid(d.datdba),'server_version',current_setting('server_version_num')::integer,'format','custom',
 'superuser',current_setting('is_superuser')='on',
 'acl',COALESCE((SELECT json_agg(json_build_object(
  'grantee',CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,
  'grantor',pg_get_userbyid(a.grantor),'privilege',a.privilege_type,'grantable',a.is_grantable)
  ORDER BY pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN '' ELSE pg_get_userbyid(a.grantee) END,
  a.privilege_type,a.is_grantable)
 FROM aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a),'[]'::json))
 FROM pg_database d WHERE d.datname=current_database()`

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("control output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func (c *Client) control(ctx context.Context, source Source, argv []string) ([]byte, error) {
	status, e := c.CheckSource(ctx, source)
	if e != nil || status != SourceRunning {
		return nil, ErrQuarantine
	}
	id, e := c.CreateExec(ctx, source.ContainerID, ExecConfig{User: "0", Cmd: argv, Env: pgEnv("")})
	if e != nil {
		return nil, ErrQuarantine
	}
	b := boundedBuffer{limit: 64 << 10}
	if e = c.StartExec(ctx, id, &b, io.Discard); e != nil {
		return nil, ErrQuarantine
	}
	code, e := c.WaitExec(ctx, id)
	if e != nil || code != 0 {
		return nil, ErrQuarantine
	}
	return b.Bytes(), nil
}
func (c *Client) sql(ctx context.Context, p Postgres, q string) ([]byte, error) {
	s, e := p.conninfo()
	if e != nil {
		return nil, ErrQuarantine
	}
	return c.control(ctx, p.Source, []string{"psql", "-XAt", "--no-password", "--dbname", s, "--command", q})
}

// PreparePostgres explicitly requires local Unix-socket authentication as an
// operator-configured PostgreSQL superuser; no credential injection or guessing.
func (c *Client) PreparePostgres(ctx context.Context, s Source) (Postgres, error) {
	return c.PreparePostgresDatabase(ctx, s, "")
}

// PreparePostgresDatabase uses the frozen discovery plan's database override.
// Swarm service labels need not exist on the task container. The override is a
// literal connection value, never URI/conninfo syntax or a shell command.
func (c *Client) PreparePostgresDatabase(ctx context.Context, s Source, database string) (Postgres, error) {
	p := Postgres{Source: s}
	status, e := c.CheckSource(ctx, s)
	if e != nil || status != SourceRunning {
		return p, ErrQuarantine
	}
	v, e := c.InspectContainer(ctx, s.ContainerID)
	if e != nil {
		return p, ErrQuarantine
	}
	for _, entry := range v.Config.Env {
		k, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch k {
		case "POSTGRES_USER":
			p.User = value
		case "POSTGRES_DB":
			p.Database = value
		}
	}
	if override := v.Config.Labels["bakabel.postgres.database"]; override != "" {
		p.Database = override
	}
	if database != "" {
		p.Database = database
	}
	if _, e = p.conninfo(); e != nil {
		return p, e
	}
	raw, e := c.sql(ctx, p, metadataSQL)
	if e != nil {
		return p, ErrQuarantine
	}
	if e = json.Unmarshal(raw, &p.Metadata); e != nil || !p.Metadata.Superuser || p.Metadata.Database != p.Database || p.Metadata.DatabaseOID == "" || p.Metadata.ClusterID == "" || p.Metadata.Owner == "" || p.Metadata.ServerVersion < 150000 || p.Metadata.Format != "custom" || p.Metadata.ACL == nil {
		return p, ErrQuarantine
	}
	raw, e = c.control(ctx, s, []string{"/usr/local/bin/pg_dump", "--version"})
	if e != nil {
		return p, ErrQuarantine
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 || fields[0] != "pg_dump" || fields[1] != "(PostgreSQL)" {
		return p, ErrQuarantine
	}
	parts := strings.Split(fields[2], ".")
	if len(parts) != 2 {
		return p, ErrQuarantine
	}
	major, e1 := strconv.Atoi(parts[0])
	minor, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || major < 15 || minor < 0 || minor >= 10000 || major != p.Metadata.ServerVersion/10000 {
		return p, ErrQuarantine
	}
	p.Metadata.ClientVersion = major*10000 + minor
	p.prepared = true
	return p, nil
}

type Dump struct {
	Source                        Source
	ExecID, RunID, Database, User string
}

func validToken(s string) bool {
	if len(s) < 16 || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// CreateDump never starts the export. The caller MUST persist creating intent
// before calling, then fsync the full Dump in persist. Errors preserve ownership.
func (c *Client) CreateDump(ctx context.Context, p Postgres, run string, persist func(Dump) error) (Dump, error) {
	d := Dump{Source: p.Source, RunID: run, Database: p.Database, User: p.User}
	if !p.prepared || !validToken(run) || persist == nil {
		return d, ErrQuarantine
	}
	conn, e := p.conninfo()
	if e != nil {
		return d, ErrQuarantine
	}
	status, e := c.CheckSource(ctx, p.Source)
	if e != nil || status != SourceRunning {
		return d, ErrQuarantine
	}
	d.ExecID, e = c.CreateExec(ctx, p.Source.ContainerID, ExecConfig{User: "0", Cmd: []string{"/usr/local/bin/pg_dump", "--no-password", "--dbname", conn, "--format=custom", "--compress=gzip:9"}, Env: pgEnv(run)})
	if e != nil {
		return d, ErrQuarantine
	}
	if e = persist(d); e != nil {
		return d, ErrQuarantine
	}
	return d, nil
}

// StreamDump is the production helper primitive. Its exit code and error MUST
// become the helper process exit status; never convert stream EOF into success.
// Stderr is deliberately discarded, not logged or inserted into dump bytes.
func (c *Client) StreamDump(ctx context.Context, d Dump, stdout io.Writer) (int, error) {
	if !validToken(d.RunID) || stdout == nil {
		return 0, ErrQuarantine
	}
	status, e := c.CheckSource(ctx, d.Source)
	if e != nil || status != SourceRunning {
		return 0, ErrQuarantine
	}
	s, e := c.PollExec(ctx, d.ExecID)
	if e != nil || s.ContainerID != d.Source.ContainerID || s.ProcessConfig.Entrypoint != "/usr/local/bin/pg_dump" {
		return 0, ErrQuarantine
	}
	if e = c.StartExec(ctx, d.ExecID, stdout, io.Discard); e != nil {
		return 0, ErrQuarantine
	}
	code, e := c.WaitExec(ctx, d.ExecID)
	if e != nil {
		return 0, ErrQuarantine
	}
	if code != 0 {
		return code, ErrDumpFailed
	}
	return 0, nil
}
