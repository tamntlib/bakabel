package docker

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Stock-source primitives from the B1 proof, without argv collection/logging.
// A matched process whose identity cannot be read fails the entire scan closed.
const scanScript = `token=$1
for f in /proc/[0-9]*/environ; do
 [ -r "$f" ] || continue
 env=$(tr '\000' '\n' < "$f" 2>/dev/null) || continue
 case "
$env
" in *"
BAKABEL_RUN_ID=$token
"*)
 p=${f%/environ}; p=${p##*/}
 IFS= read -r stat < /proc/$p/stat || exit 41
 rest=${stat##*) }; set -- $rest; shift 19; start=$1
 exe=$(readlink /proc/$p/exe) || exit 43
 printf '%s|%s|%s\n' "$p" "$start" "$exe"
 ;; esac
done`
const cancelScript = `p=$1; expected=$2; token=$3; sig=$4
case "$p" in ''|*[!0-9]*) exit 40;; esac
case "$sig" in TERM|KILL) ;; *) exit 49;; esac
IFS= read -r stat < /proc/$p/stat || exit 41
rest=${stat##*) }; set -- $rest; shift 19; actual=$1
[ "$actual" = "$expected" ] || { echo STARTTIME_MISMATCH; exit 42; }
exe=$(readlink /proc/$p/exe) || exit 43
[ "$exe" = /usr/local/bin/pg_dump ] || exit 44
env=$(tr '\000' '\n' < /proc/$p/environ) || exit 45
case "
$env
" in *"
BAKABEL_RUN_ID=$token
"*) ;; *) exit 46;; esac
IFS= read -r stat < /proc/$p/stat || exit 47
rest=${stat##*) }; set -- $rest; shift 19
[ "$1" = "$expected" ] || exit 48
kill -"$sig" "$p"`

type dumpProcess struct{ pid, start, exe string }

func (c *Client) scanDump(ctx context.Context, d Dump) ([]dumpProcess, error) {
	raw, e := c.control(ctx, d.Source, []string{"sh", "-c", scanScript, "bakabel-scan", d.RunID})
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
		if e1 != nil || e2 != nil || pid <= 1 || start == 0 || parts[2] != "/usr/local/bin/pg_dump" {
			return nil, ErrQuarantine
		}
		found = append(found, dumpProcess{parts[0], parts[1], parts[2]})
	}
	if len(found) > 1 {
		return nil, ErrQuarantine
	}
	return found, nil
}
func (c *Client) signalDump(ctx context.Context, d Dump, p dumpProcess, signal string) error {
	_, e := c.control(ctx, d.Source, []string{"sh", "-c", cancelScript, "bakabel-cancel", p.pid, p.start, d.RunID, signal})
	return e
}

// TerminalProof concerns ONLY the source export. The caller must independently
// prove its worker dead and retain ownership/quarantine on ANY returned error.
type TerminalProof struct {
	ExecNeverStarted        bool
	SourceTerminal          bool
	ExecExitCode            *int
	NoProcesses, NoSessions bool
}

func (c *Client) CancelDump(ctx context.Context, d Dump) (TerminalProof, error) {
	var proof TerminalProof
	if !validToken(d.RunID) || !validID(d.ExecID) {
		return proof, ErrQuarantine
	}
	if _, e := (Postgres{Database: d.Database, User: d.User}).conninfo(); e != nil {
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
	if e != nil || x.ContainerID != d.Source.ContainerID || x.ProcessConfig.Entrypoint != "/usr/local/bin/pg_dump" {
		return proof, ErrQuarantine
	}
	processes, e := c.scanDump(ctx, d)
	if e != nil || x.Running && len(processes) != 1 {
		return proof, ErrQuarantine
	}
	if len(processes) == 1 {
		if e = c.signalDump(ctx, d, processes[0], "TERM"); e != nil {
			return proof, ErrQuarantine
		}
		termCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, waitErr := c.WaitExec(termCtx, d.ExecID)
		cancel()
		if waitErr != nil {
			state, e := c.PollExec(ctx, d.ExecID)
			if e != nil {
				return proof, ErrQuarantine
			}
			if state.Running {
				now, e := c.scanDump(ctx, d)
				if e != nil || len(now) != 1 || now[0] != processes[0] {
					return proof, ErrQuarantine
				}
				if e = c.signalDump(ctx, d, now[0], "KILL"); e != nil {
					return proof, ErrQuarantine
				}
			}
		}
	}
	code, e := c.WaitExec(ctx, d.ExecID)
	if e != nil {
		return proof, ErrQuarantine
	}
	// SQL/backend disappearance can lag the client process by a few milliseconds.
	for {
		processes, e = c.scanDump(ctx, d)
		if e != nil || len(processes) != 0 {
			return proof, ErrQuarantine
		}
		raw, e := c.sql(ctx, Postgres{Source: d.Source, Database: d.Database, User: d.User}, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+d.RunID+"'")
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
		select {
		case <-ctx.Done():
			return proof, ErrQuarantine
		case <-time.After(100 * time.Millisecond):
		}
	}
	status, e = c.CheckSource(ctx, d.Source)
	if e != nil {
		return proof, ErrQuarantine
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
