package docker

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func restoreArgs(d RestoreExec) ([]string, error) {
	if !validToken(d.RunID) || !validID(d.ExecID) {
		return nil, ErrQuarantine
	}
	conn, e := restoreConninfo(d.Database, d.User)
	if e != nil {
		return nil, e
	}
	return []string{"--no-password", "--exit-on-error", "--dbname", conn}, nil
}
func (c *Client) inspectRestoreExec(ctx context.Context, d RestoreExec) (ExecStatus, error) {
	args, e := restoreArgs(d)
	if e != nil {
		return ExecStatus{}, e
	}
	x, e := c.PollExec(ctx, d.ExecID)
	if e != nil || x.ContainerID != d.Target.ContainerID || x.ProcessConfig.Entrypoint != "/usr/local/bin/pg_restore" || !reflect.DeepEqual(x.ProcessConfig.Arguments, args) {
		return x, ErrQuarantine
	}
	return x, nil
}
func (c *Client) scanRestore(ctx context.Context, d RestoreExec) ([]dumpProcess, error) {
	raw, e := c.control(ctx, d.Target, []string{"sh", "-c", scanScript, "bakabel-restore-scan", d.RunID})
	if e != nil {
		return nil, ErrQuarantine
	}
	var found []dumpProcess
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			return nil, ErrQuarantine
		}
		pid, e1 := strconv.ParseUint(parts[0], 10, 31)
		start, e2 := strconv.ParseUint(parts[1], 10, 64)
		if e1 != nil || e2 != nil || pid <= 1 || start == 0 || parts[2] != "/usr/local/bin/pg_restore" {
			return nil, ErrQuarantine
		}
		found = append(found, dumpProcess{parts[0], parts[1], parts[2]})
	}
	if len(found) > 1 {
		return nil, ErrQuarantine
	}
	return found, nil
}
func (c *Client) signalRestore(ctx context.Context, d RestoreExec, p dumpProcess, signal string) error {
	script := strings.ReplaceAll(cancelScript, "/usr/local/bin/pg_dump", "/usr/local/bin/pg_restore")
	_, e := c.control(ctx, d.Target, []string{"sh", "-c", script, "bakabel-restore-cancel", p.pid, p.start, d.RunID, signal})
	return e
}

// VerifyUnstartedRestoreExec is ONLY for a fenced controller that durably knows
// start was never authorized (e.g. PersistExec returned failure). A nil exit is
// not inferred to be successful execution by CancelRestoreExec.
func (c *Client) VerifyUnstartedRestoreExec(ctx context.Context, d RestoreExec) (TerminalProof, error) {
	var proof TerminalProof
	if _, e := restoreArgs(d); e != nil {
		return proof, e
	}
	status, e := c.CheckSource(ctx, d.Target)
	if e != nil {
		return proof, e
	}
	if status == SourceTerminal {
		proof.SourceTerminal = true
		return proof, nil
	}
	x, e := c.inspectRestoreExec(ctx, d)
	if e != nil || x.Running || x.Pid != 0 || x.ExitCode != nil {
		return proof, ErrQuarantine
	}
	processes, e := c.scanRestore(ctx, d)
	if e != nil || len(processes) != 0 {
		return proof, ErrQuarantine
	}
	raw, e := c.restoreSQL(ctx, Postgres{Source: d.Target, Database: d.Database, User: d.User}, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+d.RunID+"'")
	if e != nil || strings.TrimSpace(string(raw)) != "0" {
		return proof, ErrQuarantine
	}
	status, e = c.CheckSource(ctx, d.Target)
	if e != nil {
		return proof, e
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

// CancelRestoreExec is restart-safe: it uses only the persisted secret-free
// checkpoint, NEVER the former source DB or scheduler memory. Signal only an
// exact run-token/executable/PID-start identity. Failure means keep ownership
// quarantined. It never kills a container or drops the partial destination.
func (c *Client) CancelRestoreExec(ctx context.Context, d RestoreExec) (TerminalProof, error) {
	var proof TerminalProof
	if _, e := restoreArgs(d); e != nil {
		return proof, ErrQuarantine
	}
	status, e := c.CheckSource(ctx, d.Target)
	if e != nil {
		return proof, ErrQuarantine
	}
	if status == SourceTerminal {
		proof.SourceTerminal = true
		return proof, nil
	}
	x, e := c.inspectRestoreExec(ctx, d)
	if e != nil {
		return proof, e
	}
	processes, e := c.scanRestore(ctx, d)
	if e != nil {
		return proof, e
	}
	if x.Running && len(processes) != 1 {
		// A fast successful process may terminate between the two observations.
		x, e = c.inspectRestoreExec(ctx, d)
		if e != nil || x.Running {
			return proof, ErrQuarantine
		}
	}
	if len(processes) == 1 {
		if e = c.signalRestore(ctx, d, processes[0], "TERM"); e != nil {
			now, scanErr := c.scanRestore(ctx, d)
			if scanErr != nil || len(now) != 0 {
				return proof, ErrQuarantine
			}
		}
		termCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, waitErr := c.WaitExec(termCtx, d.ExecID)
		cancel()
		if waitErr != nil {
			state, e := c.inspectRestoreExec(ctx, d)
			if e != nil {
				return proof, e
			}
			if state.Running {
				now, e := c.scanRestore(ctx, d)
				if e != nil || len(now) != 1 || now[0] != processes[0] {
					return proof, ErrQuarantine
				}
				if e = c.signalRestore(ctx, d, now[0], "KILL"); e != nil {
					return proof, ErrQuarantine
				}
			}
		}
	}
	code, e := c.WaitExec(ctx, d.ExecID)
	if e != nil {
		return proof, ErrQuarantine
	}
	p := Postgres{Source: d.Target, Database: d.Database, User: d.User}
	// A killed libpq client does not prove its server query ended. Terminate only
	// this cryptographically random run's backend on the fixed target connection.
	predicate := "application_name='" + d.RunID + "' AND datname=current_database() AND usename=current_user AND pid<>pg_backend_pid()"
	for {
		now, e := c.scanRestore(ctx, d)
		if e != nil || len(now) != 0 {
			return proof, ErrQuarantine
		}
		raw, e := c.restoreSQL(ctx, p, "SELECT count(*) FROM pg_stat_activity WHERE "+predicate)
		if e != nil {
			return proof, ErrQuarantine
		}
		count, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if e != nil {
			return proof, ErrQuarantine
		}
		if count == 0 {
			break
		}
		if _, e = c.restoreSQL(ctx, p, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE "+predicate); e != nil {
			return proof, ErrQuarantine
		}
		select {
		case <-ctx.Done():
			return proof, ErrQuarantine
		case <-time.After(100 * time.Millisecond):
		}
	}
	status, e = c.CheckSource(ctx, d.Target)
	if e != nil {
		return proof, e
	}
	if status == SourceTerminal {
		proof.SourceTerminal = true
		return proof, nil
	}
	proof.ExecExitCode = &code
	proof.NoProcesses = true
	proof.NoSessions = true
	return proof, nil
}
