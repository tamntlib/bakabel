package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tamntlib/bakabel/internal/platform/docker"
	"github.com/tamntlib/bakabel/internal/state"
)

func TestConcreteLiveController(t *testing.T) {
	if os.Getenv("B1_CONCRETE_LAUNCH") != "1" {
		return
	}
	var p docker.Postgres
	var l WorkerLaunch
	if json.Unmarshal([]byte(os.Getenv("B1_POSTGRES")), &p) != nil || json.Unmarshal([]byte(os.Getenv("B1_LAUNCH")), &l) != nil {
		t.Fatal("invalid fixture launch")
	}
	o, e := state.Acquire(os.Getenv("B1_STATE"))
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	c, e := docker.NewClient(os.Getenv("B1_SOCKET"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, e = c.PreparePostgres(ctx, p.Source)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = LaunchPostgresWorker(ctx, o, c, p, l); e != nil {
		t.Fatal(e)
	}
	if _, _, e = FinishWorker(ctx, o, c, l.JobDir); e != nil {
		t.Fatal(e)
	}
}
func launchConcreteController(t *testing.T, f *fixture, l WorkerLaunch, dir string) (*exec.Cmd, state.Record) {
	t.Helper()
	bin, _ := os.Executable()
	p, _ := json.Marshal(f.p)
	launch, _ := json.Marshal(l)
	cmd := exec.Command(bin, "-test.run=^TestConcreteLiveController$")
	cmd.Env = append(os.Environ(), "B1_CONCRETE_LAUNCH=1", "B1_STATE="+dir, "B1_SOCKET="+f.socket, "B1_POSTGRES="+string(p), "B1_LAUNCH="+string(launch))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		var r state.Record
		b, e := os.ReadFile(filepath.Join(dir, "owner.json"))
		if e == nil && json.Unmarshal(b, &r) == nil && r.WorkerStartAuthorized {
			return cmd, r
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("concrete controller did not durably authorize worker")
	return nil, state.Record{}
}

func TestConcreteRecoveryController(t *testing.T) {
	if os.Getenv("B1_CONCRETE_RECOVER") != "1" {
		return
	}
	o, e := state.Acquire(os.Getenv("B1_STATE"))
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	c, e := docker.NewClient(os.Getenv("B1_SOCKET"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	proof, e := Recover(ctx, o, c, state.OutcomeCanceled)
	if os.Getenv("B1_EXPECT_BLOCK") == "1" {
		if !errors.Is(e, docker.ErrQuarantine) {
			t.Fatal("uncertainty accepted", e)
		}
		r, e := o.Load()
		if e != nil || r.Status != state.StatusBlocked || r.Phase != state.PhaseQuarantine {
			t.Fatal("quarantine not durable", r, e)
		}
		if e = o.NewRun(state.Record{RunID: "other", DaemonID: r.DaemonID, WorkerName: "other", Phase: state.PhaseIntent, Status: state.StatusActive}); !errors.Is(e, state.ErrOwned) {
			t.Fatal("new run accepted", e)
		}
		t.Log("worker uncertainty kept durable quarantine")
		return
	}
	if e != nil {
		r, _ := o.Load()
		x, xe := c.PollExec(ctx, r.ExecID)
		t.Logf("recovery diagnostic phase=%s start_auth=%v exec_running=%v exec_pid=%d exec_exit=%v entry=%s inspect_error=%v", r.Phase, r.WorkerStartAuthorized, x.Running, x.Pid, x.ExitCode, x.ProcessConfig.Entrypoint, xe)
	}
	if e != nil || !proof.NoProcesses || !proof.NoSessions || (proof.ExecExitCode == nil && !proof.ExecNeverStarted) {
		t.Fatalf("terminal proof %+v %v", proof, e)
	}
	if _, e = o.Load(); !errors.Is(e, state.ErrNoRun) {
		t.Fatal("not released", e)
	}
	exitText := "never-started"
	if proof.ExecExitCode != nil {
		exitText = strconv.Itoa(*proof.ExecExitCode)
	}
	t.Logf("fresh concrete Docker recovery source_exit=%s never_started=%v no_processes=true no_sessions=true owner=released", exitText, proof.ExecNeverStarted)
}
func freshConcrete(t *testing.T, dir, socket string, block bool) {
	t.Helper()
	bin, _ := os.Executable()
	cmd := exec.Command(bin, "-test.run=^TestConcreteRecoveryController$", "-test.v")
	cmd.Env = append(os.Environ(), "B1_CONCRETE_RECOVER=1", "B1_STATE="+dir, "B1_SOCKET="+socket)
	if block {
		cmd.Env = append(cmd.Env, "B1_EXPECT_BLOCK=1")
	}
	out, e := cmd.CombinedOutput()
	t.Logf("fresh concrete controller:\n%s", out)
	if e != nil {
		t.Fatal(e)
	}
}

func TestConcreteCreateResponseLossRecovery(t *testing.T) {
	f := realFixture(t)
	l := workerLaunchFixture(t, f)
	dir, o := ownedDir(t)
	var mu sync.Mutex
	var lostID string
	socket := faultProxy(t, f, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "POST" || r.URL.Path != "/v1.55/containers/create" {
			return false
		}
		durable, e := o.Load()
		if e != nil || durable.WorkerName == "" || durable.ExecID == "" || durable.WorkerContainerID != "" || durable.WorkerStartAuthorized {
			t.Error("create before intent/source ID", durable, e)
		}
		x, e := f.c.PollExec(f.ctx, durable.ExecID)
		if e != nil || x.Running {
			t.Error("source launched before worker", x, e)
		}
		r.RequestURI = ""
		r.URL.Scheme = "http"
		r.URL.Host = "docker"
		response, e := f.http.Transport.RoundTrip(r)
		if e != nil {
			t.Error(e)
			return true
		}
		defer response.Body.Close()
		var v struct {
			ID string `json:"Id"`
		}
		if json.NewDecoder(response.Body).Decode(&v) != nil || v.ID == "" {
			t.Error("real create missing ID")
		}
		mu.Lock()
		lostID = v.ID
		mu.Unlock()
		conn, _, e := w.(http.Hijacker).Hijack()
		if e == nil {
			conn.Close()
		} else {
			t.Error(e)
		}
		return true
	})
	c, _ := docker.NewClient(socket)
	_, e := LaunchPostgresWorker(f.ctx, o, c, f.p, l)
	if !errors.Is(e, docker.ErrQuarantine) {
		t.Fatal("create response loss accepted", e)
	}
	mu.Lock()
	id := lostID
	mu.Unlock()
	if id == "" {
		t.Fatal("no real worker create")
	}
	r, e := o.Load()
	if e != nil || r.WorkerContainerID != "" || r.Status != state.StatusBlocked || r.WorkerStartAuthorized {
		t.Fatal("lost create state", r, e)
	}
	// No cached ID is given to the new process: only Owner's random name/run labels.
	o.Close()
	freshConcrete(t, dir, f.socket, false)
	if code := f.api("GET", "/containers/"+id+"/json", nil, nil); code != 404 {
		t.Fatal("unstarted recovered worker not removed", code)
	}
	t.Log("actual create response-loss adopted and removed exact unstarted worker", id)
}

func TestConcreteWorkerKillAndFreshRecovery(t *testing.T) {
	f := realFixture(t)
	f.sql("CREATE TABLE bulk AS SELECT g,(SELECT string_agg(md5(g::text||':'||s::text),'') FROM generate_series(1,32)s) AS data FROM generate_series(1,50000)g")
	for _, mode := range []string{"lock", "stream"} {
		t.Run(mode, func(t *testing.T) {
			l := workerLaunchFixture(t, f)
			dir, o := ownedDir(t)
			var lockToken string
			if mode == "lock" {
				lockToken = token(t)
				id, e := f.c.CreateExec(f.ctx, f.id, docker.ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "-U", "postgres", "-d", "fixture", "-c", "BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90)"}, Env: []string{"PGAPPNAME=" + lockToken}})
				if e != nil {
					t.Fatal(e)
				}
				go f.c.StartExec(f.ctx, id, io.Discard, io.Discard)
				for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE application_name='"+lockToken+"' AND mode='AccessExclusiveLock' AND granted")) != "1" {
					time.Sleep(50 * time.Millisecond)
				}
				defer func() {
					f.sql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='" + lockToken + "'")
					f.c.WaitExec(f.ctx, id)
				}()
			}
			proxy := newRawProxy(t, f.socket, mode == "stream", nil)
			l.Socket = hostPath(proxy.socket)
			o.Close()
			controller, r := launchConcreteController(t, f, l, dir)
			w := recordWorker(r)
			cleanupConcreteWorker(t, f, w)
			if mode == "lock" {
				until := time.Now().Add(15 * time.Second)
				for strings.TrimSpace(f.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name='"+r.RunID+"' AND wait_event_type='Lock'")) != "1" {
					if time.Now().After(until) {
						t.Fatal("not lock waiting")
					}
					time.Sleep(50 * time.Millisecond)
				}
			} else {
				select {
				case <-proxy.seen:
					t.Log("actual stream forwarded >=32768 bytes")
				case <-time.After(20 * time.Second):
					t.Fatal("not streaming")
				}
			}
			// The guard still belongs to the controller while the actual container runs.
			if second, e := state.Acquire(dir); !errors.Is(e, state.ErrBusy) {
				if second != nil {
					second.Close()
				}
				t.Fatal("guard not held", e)
			}
			descendants := workerPIDs(t, f, w)
			if e := controller.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e := controller.Wait(); e == nil {
				t.Fatal("controller SIGKILL returned success")
			}
			wp, e := f.c.TerminateWorker(f.ctx, w)
			if e != nil || !wp.Terminal || wp.ExitCode != 137 {
				t.Fatal("worker KILL/readback", wp, e)
			}
			assertWorkerPIDsGone(t, descendants)
			x, e := f.c.PollExec(f.ctx, r.ExecID)
			if e != nil || !x.Running {
				t.Fatal("source export should survive worker SIGKILL", x, e)
			}
			// API uncertainty and wrong labels must never signal/release a different worker
			// or touch source export. Fault injection changes ONLY the real inspect response.
			for _, fault := range []string{"unavailable", "labels", "daemon"} {
				var sourceMutations atomic.Int32
				badSocket := faultProxy(t, f, func(out http.ResponseWriter, req *http.Request) bool {
					if req.Method == "POST" && (strings.HasPrefix(req.URL.Path, "/v1.55/containers/"+f.id+"/") || strings.HasPrefix(req.URL.Path, "/v1.55/exec/")) {
						sourceMutations.Add(1)
					}
					if fault == "daemon" && req.URL.Path == "/v1.55/info" {
						json.NewEncoder(out).Encode(map[string]string{"ID": "wrong-daemon"})
						return true
					}
					if req.URL.Path != "/v1.55/containers/"+w.ContainerID+"/json" {
						return false
					}
					if fault == "unavailable" {
						out.WriteHeader(503)
						return true
					}
					if fault != "labels" {
						return false
					}
					var actual map[string]any
					f.api("GET", req.URL.Path[len("/v1.55"):], nil, &actual)
					cfg := actual["Config"].(map[string]any)
					cfg["Labels"].(map[string]any)["bakabel.run"] = "not-this-run"
					json.NewEncoder(out).Encode(actual)
					return true
				})
				freshConcrete(t, dir, badSocket, true)
				// Natural broken-pipe exit can race fresh process startup. Assert no
				// recovery mutation, not that a disconnected producer must stay alive.
				if sourceMutations.Load() != 0 {
					t.Fatal("uncertain worker identity mutated source export")
				}
			}
			freshConcrete(t, dir, f.socket, false)
			snaps, e := repositoryForLaunch(l).Snapshots(f.ctx)
			if e != nil || len(snaps) != 0 {
				t.Fatal("aborted repository has snapshots", snaps, e)
			}
			t.Logf("mode=%s worker_exit=137 exact_worker=%s source initially live; fresh terminal source+process+session proof before Release", mode, w.ContainerID)
		})
	}
	v, e := f.c.InspectContainer(f.ctx, f.id)
	if e != nil || !v.State.Running || v.State.StartedAt != f.p.Source.StartedAt || v.RestartCount != 0 {
		t.Fatal("source restarted/stopped", v.State, e)
	}
}

// Host process reads are fixture evidence ONLY, not a production proof callback.
// Docker top reports host PIDs; record starttime to avoid PID-reuse assumptions.
func workerPIDs(t *testing.T, f *fixture, w docker.Worker) map[string]string {
	t.Helper()
	var top struct {
		Titles    []string
		Processes [][]string
	}
	f.api("GET", "/containers/"+w.ContainerID+"/top", nil, &top)
	index := -1
	for i, v := range top.Titles {
		if v == "PID" {
			index = i
		}
	}
	if index < 0 || len(top.Processes) < 3 {
		t.Fatal("expected actual worker/Restic/export descendants", top)
	}
	pids := map[string]string{}
	for _, p := range top.Processes {
		pid := p[index]
		tasks, e := os.ReadDir(filepath.Join("/proc", pid, "task"))
		if e != nil {
			t.Fatal(e)
		}
		for _, task := range tasks {
			status, e := os.ReadFile(filepath.Join("/proc", pid, "task", task.Name(), "status"))
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(status), "Cpus_allowed_list:\t0-1\n") {
				t.Fatal("fixture worker thread not pinned CPUs 0,1", pid, task.Name())
			}
		}
		b, e := os.ReadFile(filepath.Join("/proc", pid, "stat"))
		if e != nil {
			t.Fatal(e)
		}
		parts := strings.Fields(string(b[strings.LastIndex(string(b), ")")+1:]))
		pids[pid] = parts[19]
	}
	return pids
}
func assertWorkerPIDsGone(t *testing.T, pids map[string]string) {
	t.Helper()
	for pid, start := range pids {
		b, e := os.ReadFile(filepath.Join("/proc", pid, "stat"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		parts := strings.Fields(string(b[strings.LastIndex(string(b), ")")+1:]))
		if parts[19] == start && parts[0] != "Z" && parts[0] != "X" {
			t.Fatal("worker descendant survived terminal container", pid)
		}
	}
	t.Logf("all %d exact worker/Restic/export process identities terminal", len(pids))
}
