package docker

import (
	"context"
	"strings"
)

// VerifyUnstartedDump is ONLY for a controller that has fenced its worker and
// durably knows worker start was never authorized. Nil exec exit is NOT success:
// distinguish a never-started exec from an observed terminal process exit.
func (c *Client) VerifyUnstartedDump(ctx context.Context, d Dump) (TerminalProof, error) {
	var proof TerminalProof
	if !validToken(d.RunID) || !validID(d.ExecID) {
		return proof, ErrQuarantine
	}
	status, e := c.CheckSource(ctx, d.Source)
	if e != nil {
		return proof, ErrQuarantine
	}
	if status == SourceTerminal {
		proof.SourceTerminal = true
		return proof, nil
	}
	x, e := c.PollExec(ctx, d.ExecID)
	if e != nil || x.ContainerID != d.Source.ContainerID || x.ProcessConfig.Entrypoint != "/usr/local/bin/pg_dump" || x.Running || x.Pid != 0 || x.ExitCode != nil {
		return proof, ErrQuarantine
	}
	ps, e := c.scanDump(ctx, d)
	if e != nil || len(ps) != 0 {
		return proof, ErrQuarantine
	}
	raw, e := c.sql(ctx, Postgres{Source: d.Source, Database: d.Database, User: d.User}, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+d.RunID+"'")
	if e != nil || strings.TrimSpace(string(raw)) != "0" {
		return proof, ErrQuarantine
	}
	status, e = c.CheckSource(ctx, d.Source)
	if e != nil {
		return proof, ErrQuarantine
	}
	if status == SourceTerminal {
		proof.SourceTerminal = true
		return proof, nil
	}
	proof.ExecNeverStarted = true
	proof.NoProcesses = true
	proof.NoSessions = true
	return proof, nil
}
