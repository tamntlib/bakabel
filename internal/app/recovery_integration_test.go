package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

// TestPipelineWorker is ONLY the fixture launcher. Its producer is the separately
// compiled cmd/bakabel application, never a test shim implementing export.
func TestPipelineWorker(t *testing.T) {
	if os.Getenv("BAKABEL_B1_WORKER") != "1" {
		return
	}
	var m backup.Metadata
	var args []string
	if json.Unmarshal([]byte(os.Getenv("BAKABEL_B1_METADATA")), &m) != nil || json.Unmarshal([]byte(os.Getenv("BAKABEL_B1_ARGS")), &args) != nil {
		os.Exit(2)
	}
	o, e := state.Acquire(os.Getenv("BAKABEL_B1_STATE"))
	if e != nil {
		os.Exit(2)
	}
	record, e := o.Load()
	if e != nil || record.Phase != state.PhaseExecStarted || record.RunID != os.Getenv("BAKABEL_B1_RUN") {
		os.Exit(2)
	}
	// Deliberately hold the real durable Owner guard while the pipeline runs;
	// SIGKILL now crashes both the launcher/owner and its Restic/helper children.
	r := backup.Repository{Binary: os.Getenv("RESTIC_TEST_BINARY"), Env: os.Environ()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := r.Backup(ctx, m, os.Getenv("BAKABEL_B1_RUN"), "b1-fixture", args)
	if result.Err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// A fresh controller process has no old Client/Owner or in-memory Dump. The
// fixture's parent has reaped the worker and killed its entire process group;
// additionally verify no live member of that *exact intended group* remains.
// The fixture parent is not a production process-supervision implementation.
func TestRecoveryController(t *testing.T) {
	if os.Getenv("BAKABEL_B1_RECOVER") != "1" {
		return
	}
	o, e := state.Acquire(os.Getenv("BAKABEL_B1_STATE"))
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	c, e := docker.NewClient(os.Getenv("BAKABEL_B1_RECOVERY_SOCKET"))
	if e != nil {
		t.Fatal(e)
	}
	group, e := strconv.Atoi(os.Getenv("BAKABEL_B1_GROUP"))
	if e != nil || group < 2 {
		t.Fatal("missing fixture worker-terminal attestation")
	}
	expected := os.Getenv("BAKABEL_B1_WORKER_NAME")
	verifier := func(ctx context.Context, name string) (bool, error) {
		if name != expected {
			return false, errors.New("wrong intended worker")
		}
		entries, e := os.ReadDir("/proc")
		if e != nil {
			return false, e
		}
		for _, entry := range entries {
			pid, e := strconv.Atoi(entry.Name())
			if e != nil || pid <= 0 {
				continue
			}
			b, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return false, e
			}
			parts := strings.Fields(string(b[strings.LastIndex(string(b), ")")+1:]))
			if len(parts) < 3 {
				return false, errors.New("unknown process identity")
			}
			pg, e := strconv.Atoi(parts[2])
			if e != nil {
				return false, e
			}
			if pg == group && parts[0] != "Z" && parts[0] != "X" {
				return false, nil
			}
		}
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	proof, e := legacyRecover(ctx, o, c, verifier, state.OutcomeCanceled)
	if os.Getenv("BAKABEL_B1_EXPECT_BLOCK") == "1" {
		if !errors.Is(e, docker.ErrQuarantine) {
			t.Fatalf("expected quarantine %v", e)
		}
		record, e := o.Load()
		if e != nil || record.Status != state.StatusBlocked || record.Phase != state.PhaseQuarantine {
			t.Fatal("not durable blocked", record, e)
		}
		if !errors.Is(o.NewRun(state.Record{RunID: record.RunID, DaemonID: record.DaemonID, WorkerName: record.WorkerName, Phase: state.PhaseIntent, Status: state.StatusActive}), state.ErrOwned) {
			t.Fatal("second run not blocked")
		}
		t.Logf("durable quarantine run=%s exec=%s", record.RunID, record.ExecID)
		return
	}
	if errors.Is(e, docker.ErrQuarantine) {
		record, loadError := o.Load()
		if loadError != nil || record.Status != state.StatusBlocked || record.Phase != state.PhaseQuarantine {
			t.Fatal("transient recovery lost durable quarantine", record, loadError)
		}
		status, inspectError := c.PollExec(ctx, record.ExecID)
		exit := -999
		if status.ExitCode != nil {
			exit = *status.ExitCode
		}
		t.Logf("interim quarantine retained: running=%v exit=%d inspect=%v; another fresh controller must prove terminal", status.Running, exit, inspectError)
		// Distinct fixture-only exit: parent may launch at most two further NEW
		// controllers. This is not an in-process retry or a release without proof.
		o.Close()
		os.Exit(3)
	}
	if e != nil || (!proof.SourceTerminal && (proof.ExecExitCode == nil || !proof.NoProcesses || !proof.NoSessions)) {
		t.Fatalf("recovery proof %+v %v", proof, e)
	}
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("release readback", e)
	}
	t.Logf("fresh recovery terminal exit=%d no_processes=%v no_sessions=%v ownership=released", *proof.ExecExitCode, proof.NoProcesses, proof.NoSessions)
}

// rawProxy forwards the actual Docker byte stream (including HTTP upgrade), not
// a fabricated API. It can throttle or disconnect only exec_start connections.
type rawProxy struct {
	socket   string
	listener net.Listener
	mu       sync.Mutex
	conns    []net.Conn
	streams  []net.Conn
	seen     chan struct{}
	once     sync.Once
	slow     bool
	tap      io.WriteCloser
}

func newRawProxy(t *testing.T, upstream string, slow bool, tap io.WriteCloser) *rawProxy {
	t.Helper()
	p := &rawProxy{socket: filepath.Join(t.TempDir(), "docker.sock"), seen: make(chan struct{}), slow: slow, tap: tap}
	var e error
	p.listener, e = net.Listen("unix", p.socket)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		p.listener.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			c.Close()
		}
	})
	go func() {
		for {
			down, e := p.listener.Accept()
			if e != nil {
				return
			}
			go func() {
				up, e := net.Dial("unix", upstream)
				if e != nil {
					down.Close()
					return
				}
				p.mu.Lock()
				p.conns = append(p.conns, up, down)
				p.mu.Unlock()
				// All requests emitted by net/http fit in this initial read for fixture API.
				b := make([]byte, 65536)
				n, e := down.Read(b)
				if e != nil {
					up.Close()
					down.Close()
					return
				}
				start := strings.Contains(string(b[:n]), "/exec/") && strings.Contains(string(b[:n]), "/start ")
				if start {
					if p.tap != nil {
						defer p.tap.Close()
					}
					p.mu.Lock()
					p.streams = append(p.streams, up, down)
					p.mu.Unlock()
				}
				if _, e = up.Write(b[:n]); e != nil {
					return
				}
				go io.Copy(up, down)
				total := 0
				buffer := make([]byte, 4096)
				for {
					n, e := up.Read(buffer)
					if n > 0 {
						if start && p.tap != nil {
							if _, e := p.tap.Write(buffer[:n]); e != nil {
								break
							}
						}
						if _, we := down.Write(buffer[:n]); we != nil {
							break
						}
						if start {
							total += n
							if total >= 32768 {
								p.once.Do(func() { close(p.seen) })
							}
							if p.slow {
								time.Sleep(50 * time.Millisecond)
							}
						}
					}
					if e != nil {
						break
					}
				}
				down.Close()
				up.Close()
			}()
		}
	}()
	return p
}
func (p *rawProxy) disconnect() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.streams {
		c.Close()
	}
}

// One Wait goroutine owns os/exec.Cmd. Cleanup and the test may both await it,
// but must never concurrently call Cmd.Wait on timeout/failure paths.
type pipelineProcess struct {
	*exec.Cmd
	done chan struct{}
	err  error
}

func (p *pipelineProcess) Wait() error { <-p.done; return p.err }
func launchPipeline(t *testing.T, f *fixture, r backup.Repository, run, stateDir string, args []string) *pipelineProcess {
	t.Helper()
	bin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	m, _ := json.Marshal(metadata(f.p))
	a, _ := json.Marshal(args)
	cmd := exec.Command(bin, "-test.run=^TestPipelineWorker$")
	cmd.Env = append(r.Env, "BAKABEL_B1_WORKER=1", "BAKABEL_B1_METADATA="+string(m), "BAKABEL_B1_ARGS="+string(a), "BAKABEL_B1_RUN="+run, "BAKABEL_B1_STATE="+stateDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	managed := &pipelineProcess{Cmd: cmd, done: make(chan struct{})}
	go func() { managed.err = cmd.Wait(); close(managed.done) }()
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); managed.Wait() })
	return managed
}
func freshRecovery(t *testing.T, dir, socket, worker string, group int, block bool) {
	t.Helper()
	bin, _ := os.Executable()
	for attempt := 1; attempt <= 3; attempt++ {
		cmd := exec.Command(bin, "-test.run=^TestRecoveryController$", "-test.v")
		cmd.Env = append(os.Environ(), "BAKABEL_B1_RECOVER=1", "BAKABEL_B1_STATE="+dir, "BAKABEL_B1_RECOVERY_SOCKET="+socket, "BAKABEL_B1_GROUP="+strconv.Itoa(group), "BAKABEL_B1_WORKER_NAME="+worker)
		if block {
			cmd.Env = append(cmd.Env, "BAKABEL_B1_EXPECT_BLOCK=1")
		}
		out, e := cmd.CombinedOutput()
		t.Logf("fresh controller attempt=%d\n%s", attempt, out)
		if e == nil {
			return
		}
		var exit *exec.ExitError
		if !block && errors.As(e, &exit) && exit.ExitCode() == 3 && attempt < 3 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		t.Fatal("fresh controller", e)
	}
}
func ownedDir(t *testing.T) (string, *state.Owner) {
	t.Helper()
	dir := t.TempDir()
	o, e := state.Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { o.Close() })
	return dir, o
}

func TestRealWorkerDeathsAndDockerDisconnect(t *testing.T) {
	f := realFixture(t)
	// Enough incompressible-ish source bytes to prove active streaming rather than
	// a helper that finished before SIGKILL. No full dump is staged locally.
	f.sql("CREATE TABLE bulk AS SELECT g,(SELECT string_agg(md5(g::text||':'||s::text),'') FROM generate_series(1,32)s) AS data FROM generate_series(1,50000)g")
	for _, mode := range []string{"lock-sigkill", "stream-sigkill", "raw-disconnect", "source-failure", "lock-timeout", "upload-failure"} {
		t.Run(mode, func(t *testing.T) {
			r := repoFixture(t, f.ctx)
			dir, o := ownedDir(t)
			run := token(t)
			worker := "helper-" + run
			var lockID string
			if strings.HasPrefix(mode, "lock-") {
				lockToken := token(t)
				id, e := f.c.CreateExec(f.ctx, f.id, docker.ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "-U", "postgres", "-d", "fixture", "-c", "BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(120)"}, Env: []string{"PGAPPNAME=" + lockToken}})
				if e != nil {
					t.Fatal(e)
				}
				lockID = id
				go f.c.StartExec(f.ctx, id, io.Discard, io.Discard)
				for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE application_name='"+lockToken+"' AND mode='AccessExclusiveLock' AND granted")) != "1" {
					select {
					case <-f.ctx.Done():
						t.Fatal("lock timeout")
					case <-time.After(50 * time.Millisecond):
					}
				}
				defer func() {
					f.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='" + lockToken + "'")
					f.c.WaitExec(f.ctx, lockID)
				}()
			}
			d, e := Prepare(f.ctx, o, f.c, f.p, run, worker)
			if e != nil {
				t.Fatal(e)
			}
			proxy := newRawProxy(t, f.socket, mode == "stream-sigkill" || mode == "raw-disconnect", nil)
			timeout := 90 * time.Second
			if mode == "lock-timeout" || mode == "upload-failure" {
				timeout = 2 * time.Second
			}
			args, e := Authorize(o, proxy.socket, d, timeout)
			if e != nil {
				t.Fatal(e)
			}
			o.Close()
			cmd := launchPipeline(t, f, r, run, dir, append([]string{"--stdin-from-command", "--stdin-filename", "postgres.dump", "--", f.bin}, args...))
			if strings.HasPrefix(mode, "lock-") {
				for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='"+run+"' AND wait_event_type='Lock'")) != "1" {
					select {
					case <-f.ctx.Done():
						t.Fatal("dump lock wait timeout")
					case <-time.After(50 * time.Millisecond):
					}
				}
			} else {
				select {
				case <-proxy.seen:
					t.Log("real Docker stream forwarded >=32768 bytes")
				case <-time.After(30 * time.Second):
					t.Fatal("dump did not stream")
				}
			}
			if contender, e := state.Acquire(dir); !errors.Is(e, state.ErrBusy) {
				if contender != nil {
					contender.Close()
				}
				t.Fatalf("live pipeline did not own guard: %v", e)
			}
			var restoreRepository func()
			if mode == "upload-failure" {
				var repository string
				for _, v := range r.Env {
					if strings.HasPrefix(v, "RESTIC_REPOSITORY=") {
						repository = strings.TrimPrefix(v, "RESTIC_REPOSITORY=")
					}
				}
				if repository == "" {
					t.Fatal("missing owned fixture repository")
				}
				offline := repository + ".offline"
				if e = os.Rename(repository, offline); e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(repository, []byte("disposable local repository fault"), 0600); e != nil {
					t.Fatal(e)
				}
				restored := false
				restoreRepository = func() {
					if restored {
						return
					}
					if e = os.Remove(repository); e != nil {
						t.Error(e)
					}
					if e = os.Rename(offline, repository); e != nil {
						t.Error(e)
					}
					restored = true
				}
				defer restoreRepository()
			}
			if mode == "source-failure" {
				f.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='" + run + "'")
			}
			if mode == "raw-disconnect" || mode == "source-failure" || mode == "lock-timeout" || mode == "upload-failure" {
				if mode == "raw-disconnect" {
					proxy.disconnect()
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("failed producer pipeline succeeded")
					}
				case <-time.After(20 * time.Second):
					t.Fatal("producer failure failed to stop local pipeline")
				}
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			} else {
				if e = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); e != nil {
					t.Fatal(e)
				}
				if e = cmd.Wait(); e == nil {
					t.Fatal("SIGKILL succeeded")
				}
			}
			if restoreRepository != nil {
				restoreRepository()
			}
			status, e := f.c.PollExec(f.ctx, d.ExecID)
			if e != nil || (mode != "source-failure" && mode != "upload-failure" && !status.Running) {
				t.Fatalf("source must remain live after local worker loss: %+v %v", status, e)
			}
			o, e = state.Acquire(dir)
			if e != nil {
				t.Fatal("crashed owner guard not recoverable", e)
			}
			durable, e := o.Load()
			if e != nil || durable.ExecID != d.ExecID {
				t.Fatal("lost durable ownership", durable, e)
			}
			if !errors.Is(o.NewRun(state.Record{RunID: token(t), DaemonID: d.Source.DaemonID, WorkerName: "another", Phase: state.PhaseIntent, Status: state.StatusActive}), state.ErrOwned) {
				t.Fatal("overlap accepted")
			}
			o.Close()
			// Real Engine disconnection during recovery must durably quarantine without
			// releasing the live export. A subsequent fresh process repairs from state.
			if strings.HasPrefix(mode, "lock-") {
				inspectFault := make(chan struct{}, 1)
				unknownSocket := faultProxy(t, f, func(w http.ResponseWriter, r *http.Request) bool {
					if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/exec/"+d.ExecID+"/json") {
						select {
						case inspectFault <- struct{}{}:
						default:
						}
						http.Error(w, "injected inspect uncertainty", http.StatusServiceUnavailable)
						return true
					}
					return false
				})
				freshRecovery(t, dir, unknownSocket, worker, cmd.Process.Pid, true)
				select {
				case <-inspectFault:
					t.Log("exact persisted dump exec inspect fault reached")
				default:
					t.Fatal("recovery never reached exact exec inspect fault")
				}
			}
			freshRecovery(t, dir, filepath.Join(t.TempDir(), "disconnected.sock"), worker, cmd.Process.Pid, true)
			live, e := f.c.PollExec(f.ctx, d.ExecID)
			if e != nil || (mode != "source-failure" && mode != "upload-failure" && !live.Running) {
				t.Fatal("blocked recovery touched export", live, e)
			}
			freshRecovery(t, dir, f.socket, worker, cmd.Process.Pid, false)
			snapshots, e := r.Snapshots(f.ctx)
			if e != nil || len(snapshots) != 0 {
				t.Fatal("aborted producer created snapshot", snapshots, e)
			}
			terminal, e := f.c.PollExec(f.ctx, d.ExecID)
			if e != nil || terminal.Running || terminal.ExitCode == nil || (mode == "source-failure" && *terminal.ExitCode == 0) {
				t.Fatal("cancel terminal readback", terminal, e)
			}
			t.Logf("mode=%s run=%s running_after_loss=%v fresh CancelDump exit=%d snapshots=0", mode, run, status.Running, *terminal.ExitCode)
		})
	}
	final, e := f.c.InspectContainer(f.ctx, f.id)
	if e != nil || !final.State.Running || final.State.StartedAt != f.p.Source.StartedAt || final.RestartCount != 0 {
		t.Fatal("source lifecycle changed", final.State, e)
	}
}
