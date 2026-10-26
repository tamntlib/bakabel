package docker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This is a unit Engine peer, not evidence from a live Docker/PostgreSQL source.
// It exercises the public cancellation and never-started proof boundaries.
type completionCancelPeer struct {
	mu                 sync.Mutex
	d                  Dump
	cmd                []string
	cfg                ExecConfig
	running            bool
	exit               *int
	pid                int
	polls, scans, sqls int
	signals            []string
	onPoll             func(*completionCancelPeer)
	onScan             func(*completionCancelPeer) string
	unavailable        bool
	unknown            bool
}

func newCompletionCancelPeer(t *testing.T, legacy bool) (*Client, *completionCancelPeer) {
	t.Helper()
	d := Dump{Source: Source{"daemon", "source", "start"}, ExecID: "dumpexec", RunID: "bakabel_0123456789abcdef0123456789abcdef", Database: "fixture", User: "postgres"}
	cmd, err := dumpCommand(d)
	if legacy {
		cmd, err = legacyDumpCommand(d)
	}
	if err != nil {
		t.Fatal(err)
	}
	code := 7
	p := &completionCancelPeer{d: d, cmd: cmd, exit: &code}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		switch r.URL.Path {
		case "/v1.55/info":
			w.Write([]byte(`{"ID":"daemon"}`))
		case "/v1.55/containers/source/json":
			w.Write([]byte(`{"Id":"source","State":{"Running":true,"StartedAt":"start"}}`))
		case "/v1.55/exec/dumpexec/json":
			p.polls++
			if p.onPoll != nil {
				p.onPoll(p)
			}
			if p.unknown {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if p.unavailable {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close() // genuine transport loss, not a synthetic success
				}
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ID": p.d.ExecID, "ContainerID": p.d.Source.ContainerID, "Running": p.running, "Pid": p.pid, "ExitCode": p.exit, "ProcessConfig": map[string]any{"entrypoint": p.cmd[0], "arguments": p.cmd[1:]}})
		case "/v1.55/containers/source/exec":
			if err := json.NewDecoder(r.Body).Decode(&p.cfg); err != nil {
				t.Error(err)
			}
			w.Write([]byte(`{"Id":"control"}`))
		case "/v1.55/exec/control/start":
			switch {
			case len(p.cfg.Cmd) > 0 && p.cfg.Cmd[0] == "psql":
				p.sqls++
				if !strings.Contains(p.cfg.Cmd[len(p.cfg.Cmd)-1], "application_name='"+p.d.RunID+"'") {
					t.Error("SQL proof did not retain run identity")
				}
				w.Write(frame(1, "0\n"))
			case len(p.cfg.Cmd) > 2 && p.cfg.Cmd[2] == scanScript:
				p.scans++
				if p.onScan != nil {
					w.Write(frame(1, p.onScan(p)))
				}
			case len(p.cfg.Cmd) > 2 && p.cfg.Cmd[2] == cancelScript:
				args := p.cfg.Cmd[len(p.cfg.Cmd)-4:]
				if strings.Join(args[:3], "|") != "123|777|"+p.d.RunID {
					t.Error("signal was not pinned to the observed pg_dump PID/start/run", args)
				}
				p.signals = append(p.signals, args[3])
			default:
				t.Error("unexpected control command")
				w.WriteHeader(http.StatusBadRequest)
			}
		case "/v1.55/exec/control/json":
			w.Write([]byte(`{"ID":"control","ContainerID":"source","Running":false,"ExitCode":0}`))
		default:
			t.Error("unexpected Engine path", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	socket := filepath.Join(t.TempDir(), "unit-engine.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	peer := httptest.NewUnstartedServer(handler)
	peer.Listener.Close()
	peer.Listener = listener
	peer.Start()
	t.Cleanup(peer.Close)
	c, err := NewClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, p
}

func assertCompletionCancelProof(t *testing.T, proof TerminalProof, err error, code int) {
	t.Helper()
	if err != nil || proof.ExecNeverStarted || proof.SourceTerminal || proof.ExecExitCode == nil || *proof.ExecExitCode != code || !proof.NoProcesses || !proof.NoSessions {
		t.Fatalf("expected exact terminal exec + zero-process/session proof, got %+v, %v", proof, err)
	}
}

func TestCompletionCancelTerminalWrapperIdentity(t *testing.T) {
	c, p := newCompletionCancelPeer(t, false)
	proof, err := c.CancelDump(context.Background(), p.d)
	assertCompletionCancelProof(t, proof, err, 7)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scans != 2 || p.sqls != 1 || len(p.signals) != 0 {
		t.Fatal("terminal wrapper did not retain independent absence proofs", p.scans, p.sqls, p.signals)
	}
}

func TestCompletionCancelMissingChildReobserves(t *testing.T) {
	for _, tc := range []struct {
		name         string
		childAppears bool
	}{
		{"pre_child_window", true},
		{"post_child_window", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, p := newCompletionCancelPeer(t, false)
			p.running = true
			p.onScan = func(p *completionCancelPeer) string {
				if tc.childAppears && p.scans > 1 && len(p.signals) == 0 {
					return "123|777|/usr/local/bin/pg_dump\n"
				}
				return ""
			}
			p.onPoll = func(p *completionCancelPeer) {
				if (!tc.childAppears && p.scans >= 2) || len(p.signals) > 0 {
					p.running = false
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proof, err := c.CancelDump(ctx, p.d)
			assertCompletionCancelProof(t, proof, err, 7)
			p.mu.Lock()
			defer p.mu.Unlock()
			wantSignals := ""
			if tc.childAppears {
				wantSignals = "TERM"
			}
			if p.scans < 3 || strings.Join(p.signals, ",") != wantSignals {
				t.Fatal("missing-child window was not safely reobserved", p.scans, p.signals)
			}
		})
	}
}

func TestCompletionCancelPostTERMChildDisappears(t *testing.T) {
	c, p := newCompletionCancelPeer(t, false)
	p.running = true
	p.onScan = func(p *completionCancelPeer) string {
		if len(p.signals) == 0 {
			return "123|777|/usr/local/bin/pg_dump\n"
		}
		return ""
	}
	p.onPoll = func(p *completionCancelPeer) {
		// Keep the shell running through the TERM grace period and the first
		// post-TERM absence observation, then let its trailer path terminate.
		if len(p.signals) > 0 && p.scans >= 3 {
			p.running = false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	proof, err := c.CancelDump(ctx, p.d)
	assertCompletionCancelProof(t, proof, err, 7)
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Join(p.signals, ",") != "TERM" || p.scans < 4 {
		t.Fatal("post-TERM wrapper disappearance caused premature escalation", p.signals, p.scans)
	}
}

func TestCompletionUnstartedExactIdentity(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "wrapper"
		if legacy {
			name = "legacy_direct"
		}
		t.Run(name, func(t *testing.T) {
			c, p := newCompletionCancelPeer(t, legacy)
			p.exit = nil
			proof, err := c.VerifyUnstartedDump(context.Background(), p.d)
			if err != nil || !proof.ExecNeverStarted || proof.SourceTerminal || proof.ExecExitCode != nil || !proof.NoProcesses || !proof.NoSessions {
				t.Fatalf("exact unstarted exec was not proved: %+v, %v", proof, err)
			}
		})
	}
}

func TestCompletionCancelTerminalIdentityMustStillMatch(t *testing.T) {
	c, p := newCompletionCancelPeer(t, false)
	p.running = true
	p.onScan = func(p *completionCancelPeer) string {
		if len(p.signals) == 0 {
			return "123|777|/usr/local/bin/pg_dump\n"
		}
		return ""
	}
	p.onPoll = func(p *completionCancelPeer) {
		if len(p.signals) > 0 {
			p.running = false
			p.cmd[2] += "\n: mutated"
		}
	}
	proof, err := c.CancelDump(context.Background(), p.d)
	if !errors.Is(err, ErrQuarantine) || proof.ExecExitCode != nil || proof.NoProcesses || proof.NoSessions {
		t.Fatalf("terminal exec identity mutation released ownership: %+v %v", proof, err)
	}
}

func TestCompletionCancelTransientWaitFailureQuarantines(t *testing.T) {
	c, p := newCompletionCancelPeer(t, false)
	p.running = true
	p.onScan = func(p *completionCancelPeer) string {
		return "123|777|/usr/local/bin/pg_dump\n"
	}
	p.onPoll = func(p *completionCancelPeer) {
		// One unavailable inspect during TERM wait, followed by a recoverable
		// peer. Availability returning must not turn this into KILL permission.
		p.unknown = len(p.signals) == 1 && p.polls == 2
		if len(p.signals) > 1 {
			p.running = false
			p.onScan = nil
		}
	}
	proof, err := c.CancelDump(context.Background(), p.d)
	if !errors.Is(err, ErrQuarantine) || proof.NoProcesses || proof.NoSessions || proof.ExecExitCode != nil {
		t.Fatalf("unavailable TERM wait became terminal proof: %+v %v", proof, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Join(p.signals, ",") != "TERM" {
		t.Fatal("unavailable wait escalated instead of quarantining", p.signals)
	}
}

func TestCompletionExportMutatedIdentityQuarantines(t *testing.T) {
	mutations := []struct {
		name   string
		legacy bool
		mutate func(*completionCancelPeer)
	}{
		{"fixed_script", false, func(p *completionCancelPeer) { p.cmd[2] += "\n:" }},
		{"run", false, func(p *completionCancelPeer) { p.cmd[4] = "bakabel_other_0123456789abcdef" }},
		{"conninfo", false, func(p *completionCancelPeer) { p.cmd[7] += " hostaddr=127.0.0.1" }},
		{"legacy_conninfo", true, func(p *completionCancelPeer) { p.cmd[3] += " hostaddr=127.0.0.1" }},
		{"bare_legacy_entrypoint", true, func(p *completionCancelPeer) { p.cmd = p.cmd[:1] }},
		{"extra_arg", false, func(p *completionCancelPeer) { p.cmd = append(p.cmd, "--schema=other") }},
	}
	for _, unstarted := range []bool{false, true} {
		name := "cancel/"
		if unstarted {
			name = "unstarted/"
		}
		for _, tc := range mutations {
			t.Run(name+tc.name, func(t *testing.T) {
				c, p := newCompletionCancelPeer(t, tc.legacy)
				tc.mutate(p)
				var proof TerminalProof
				var err error
				if unstarted {
					p.exit = nil
					proof, err = c.VerifyUnstartedDump(context.Background(), p.d)
				} else {
					proof, err = c.CancelDump(context.Background(), p.d)
				}
				if !errors.Is(err, ErrQuarantine) || proof != (TerminalProof{}) {
					t.Fatalf("mutated identity released ownership: %+v %v", proof, err)
				}
				p.mu.Lock()
				defer p.mu.Unlock()
				if p.scans != 0 || p.sqls != 0 || len(p.signals) != 0 {
					t.Fatal("mutated exec reached process/session controls")
				}
			})
		}
	}
}

func TestCompletionCancelMissingChildQuarantineBounded(t *testing.T) {
	for _, name := range []string{"still_running", "unknown_after_scan", "transport_after_scan", "outer_deadline"} {
		t.Run(name, func(t *testing.T) {
			c, p := newCompletionCancelPeer(t, false)
			p.running = true
			p.onPoll = func(p *completionCancelPeer) {
				if p.scans > 0 {
					p.unknown = name == "unknown_after_scan"
					p.unavailable = name == "transport_after_scan"
				}
			}
			ctx := context.Background()
			if name == "outer_deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
				defer cancel()
			}
			start := time.Now()
			proof, err := c.CancelDump(ctx, p.d)
			elapsed := time.Since(start)
			if !errors.Is(err, ErrQuarantine) || proof != (TerminalProof{}) {
				t.Fatalf("missing child released ownership: %+v %v", proof, err)
			}
			limit := 2 * time.Second
			if name == "outer_deadline" {
				limit = 750 * time.Millisecond
			}
			if elapsed > limit {
				t.Fatal("missing-child wait exceeded its bound", elapsed)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.scans < 1 || p.polls < 2 || len(p.signals) != 0 || p.sqls != 0 {
				t.Fatal("absence was not reobserved safely", p.scans, p.polls, p.signals, p.sqls)
			}
		})
	}
}

func TestCompletionCancelEscalationRequiresSameChild(t *testing.T) {
	for _, name := range []string{"same_child", "reused_pid", "shell_still_running"} {
		t.Run(name, func(t *testing.T) {
			c, p := newCompletionCancelPeer(t, false)
			p.running = true
			p.onScan = func(p *completionCancelPeer) string {
				if len(p.signals) > 1 {
					return ""
				}
				if len(p.signals) == 1 {
					if name == "reused_pid" {
						return "123|778|/usr/local/bin/pg_dump\n"
					}
					if name == "shell_still_running" {
						return ""
					}
				}
				return "123|777|/usr/local/bin/pg_dump\n"
			}
			p.onPoll = func(p *completionCancelPeer) {
				if len(p.signals) > 1 {
					p.running = false
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			proof, err := c.CancelDump(ctx, p.d)
			if name == "same_child" {
				assertCompletionCancelProof(t, proof, err, 7)
			} else if !errors.Is(err, ErrQuarantine) || proof != (TerminalProof{}) {
				t.Fatalf("unsafe escalation released ownership: %+v %v", proof, err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			want := "TERM"
			if name == "same_child" {
				want += ",KILL"
			}
			if strings.Join(p.signals, ",") != want {
				t.Fatal("unsafe signal sequence", p.signals)
			}
		})
	}
}

func TestCompletionCancelExactLegacyTerminalIdentity(t *testing.T) {
	c, p := newCompletionCancelPeer(t, true)
	proof, err := c.CancelDump(context.Background(), p.d)
	assertCompletionCancelProof(t, proof, err, 7)
}
