package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Test-only process shim exercises the real exported production helper primitive.
// The application binary's internal command wiring is owned by the parent task.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("BAKABEL_TEST_HELPER") != "1" {
		return
	}
	raw, e := os.ReadFile(os.Getenv("BAKABEL_DUMP_STATE"))
	if e != nil {
		os.Exit(2)
	}
	var d Dump
	if json.Unmarshal(raw, &d) != nil {
		os.Exit(2)
	}
	c, e := NewClient(os.Getenv("BAKABEL_DOCKER_SOCKET"))
	if e != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	code, e := c.StreamDump(ctx, d, os.Stdout)
	if e != nil && code == 0 {
		code = 1
	}
	os.Exit(code)
}

type countSink struct {
	bytes int64
	magic string
}

func (s *countSink) Write(p []byte) (int, error) {
	s.bytes += int64(len(p))
	if len(s.magic) < 5 {
		s.magic += string(p[:min(len(p), 5-len(s.magic))])
	}
	return len(p), nil
}
func TestRealDockerHelperAndCancellation(t *testing.T) {
	socket := os.Getenv("BAKABEL_DOCKER_SOCKET")
	if socket == "" {
		t.Skip("explicit disposable Docker fixture opt-in required")
	}
	c, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := fmt.Sprintf("bakabel-go-docker-uzseflcy-%d", time.Now().UnixNano())
	var created struct {
		ID string `json:"Id"`
	}
	cfg := map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"sh", "-c", "while [ ! -e /tmp/bakabel-init-ready ]; do sleep 0.1; done; exec docker-entrypoint.sh postgres"}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_DB=fixture", "POSTGRES_USER=postgres"}, "HostConfig": map[string]any{"NanoCpus": 2000000000, "CpusetCpus": "0,1", "NetworkMode": "none"}}
	if e = c.request(ctx, "POST", "/containers/create?name="+name, cfg, &created); e != nil {
		t.Fatal(e)
	}
	if created.ID == "" {
		t.Fatal("missing fixture ID")
	}
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if e := c.request(clean, "DELETE", "/containers/"+created.ID+"?force=true&v=true", nil, nil); e != nil {
			t.Error("fixture cleanup", e)
		}
		_, e := c.InspectContainer(clean, created.ID)
		if e != apiError(404) {
			t.Error("cleanup readback", e)
		}
	})
	if e = c.request(ctx, "POST", "/containers/"+created.ID+"/start", nil, nil); e != nil {
		t.Fatal(e)
	}
	s, e := c.CaptureSource(ctx, created.ID)
	if e != nil {
		t.Fatal(e)
	}
	initState, e := c.InspectContainer(ctx, s.ContainerID)
	if e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command("taskset", "-pc", "0,1", strconv.Itoa(initState.State.Pid)).CombinedOutput(); e != nil {
		t.Fatalf("fixture host affinity requires test runner --pid host: %s %v", out, e)
	}
	if _, e = c.control(ctx, s, []string{"sh", "-c", ": > /tmp/bakabel-init-ready"}); e != nil {
		t.Fatal(e)
	}
	for attempts := 0; ; attempts++ {
		_, e = c.control(ctx, s, []string{"pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "fixture"})
		if e == nil {
			break
		}
		if attempts == 30 {
			v, inspectErr := c.InspectContainer(ctx, s.ContainerID)
			t.Logf("readiness diagnostic state=%+v inspect=%v control=%v", v.State, inspectErr, e)
			id, createErr := c.CreateExec(ctx, s.ContainerID, ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "-h", "127.0.0.1", "-U", "postgres", "-d", "fixture", "-c", "SELECT 1"}, Env: pgEnv("")})
			var debug strings.Builder
			startErr := c.StartExec(ctx, id, &debug, &debug)
			state, pollErr := c.PollExec(ctx, id)
			t.Fatalf("readiness diagnostic create=%v start=%v poll=%v status=%+v output=%q", createErr, startErr, pollErr, state, debug.String())
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture readiness", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	p, e := c.PreparePostgres(ctx, s)
	if e != nil {
		t.Fatal("prepare", e)
	}
	if p.Metadata.ClientVersion != 180006 || p.Metadata.ServerVersion != 180006 || p.Metadata.ClusterID == "" || p.Metadata.DatabaseOID == "" {
		t.Fatal(p.Metadata)
	}
	if _, e = c.sql(ctx, p, "CREATE TABLE payload AS SELECT g,repeat(md5(g::text),20) AS data FROM generate_series(1,20000) g"); e != nil {
		t.Fatal(e)
	}
	affinity, e := c.control(ctx, s, []string{"sh", "-c", "while IFS= read -r line; do case \"$line\" in Cpus_allowed_list*) printf '%s\\n' \"$line\";; esac; done < /proc/1/status"})
	if e != nil || !strings.Contains(string(affinity), "0-1") {
		t.Fatal("source affinity", string(affinity), e)
	}
	t.Logf("fixture=%s source=%s daemon=%s started=%s versions=%d/%d affinity=%s", name, s.ContainerID, s.DaemonID, s.StartedAt, p.Metadata.ServerVersion, p.Metadata.ClientVersion, strings.TrimSpace(string(affinity)))
	dir := t.TempDir()
	persist := func(file string) func(Dump) error {
		return func(d Dump) error {
			raw, e := json.Marshal(d)
			if e != nil {
				return e
			}
			f, e := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if e != nil {
				return e
			}
			defer f.Close()
			if _, e = f.Write(raw); e != nil {
				return e
			}
			return f.Sync()
		}
	}
	launch := func(file string, sink io.Writer) *exec.Cmd {
		t.Helper()
		bin, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(bin, "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(), "BAKABEL_TEST_HELPER=1", "BAKABEL_DUMP_STATE="+file)
		cmd.Stdout = sink
		cmd.Stderr = io.Discard
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		return cmd
	}
	successFile := filepath.Join(dir, "success.json")
	d, e := c.CreateDump(ctx, p, "bakabel_success_0123456789abcdef", persist(successFile))
	if e != nil {
		t.Fatal(e)
	}
	sink := &countSink{}
	helper := launch(successFile, sink)
	if e = helper.Wait(); e != nil {
		t.Fatal("success helper", e)
	}
	status, e := c.PollExec(ctx, d.ExecID)
	if e != nil || status.Running || status.ExitCode == nil || *status.ExitCode != 0 || sink.magic != "PGDMP" || sink.bytes <= 5 {
		t.Fatal(status, e, sink)
	}
	t.Logf("helper success exec=%s exit=%d stdout=%d magic=%q", d.ExecID, *status.ExitCode, sink.bytes, sink.magic)
	// A real pg_dump failure must leave the helper nonzero, not stream-EOF success.
	failFile := filepath.Join(dir, "failure.json")
	bad := p
	bad.Database = "missing_fixture_database"
	failed, e := c.CreateDump(ctx, bad, "bakabel_failure_0123456789abcdef", persist(failFile))
	if e != nil {
		t.Fatal(e)
	}
	if e = launch(failFile, io.Discard).Wait(); e == nil {
		t.Fatal("failed source returned helper success")
	}
	failure, e := c.PollExec(ctx, failed.ExecID)
	if e != nil || failure.ExitCode == nil || *failure.ExitCode == 0 {
		t.Fatal(failure, e)
	}
	t.Logf("helper failure exec=%s exit=%d", failed.ExecID, *failure.ExitCode)
	lockToken := "bakabel_lock_0123456789abcdef"
	conn, _ := p.conninfo()
	lockID, e := c.CreateExec(ctx, s.ContainerID, ExecConfig{User: "0", Cmd: []string{"psql", "-XAt", "--no-password", "--dbname", conn, "--command", "BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90);"}, Env: pgEnv(lockToken)})
	if e != nil {
		t.Fatal(e)
	}
	lockCtx, stopLock := context.WithCancel(ctx)
	defer stopLock()
	go c.StartExec(lockCtx, lockID, io.Discard, io.Discard)
	for {
		raw, e := c.sql(ctx, p, "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE application_name='"+lockToken+"' AND mode='AccessExclusiveLock' AND granted")
		if e == nil && strings.TrimSpace(string(raw)) == "1" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("lock timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
	lockedFile := filepath.Join(dir, "locked.json")
	locked, e := c.CreateDump(ctx, p, "bakabel_cancel_0123456789abcdef", persist(lockedFile))
	if e != nil {
		t.Fatal(e)
	}
	worker := launch(lockedFile, io.Discard)
	defer func() {
		if worker.ProcessState == nil {
			worker.Process.Kill()
			worker.Wait()
		}
	}()
	for {
		raw, e := c.sql(ctx, p, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+locked.RunID+"' AND wait_event_type='Lock'")
		if e == nil && strings.TrimSpace(string(raw)) == "1" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("dump lock wait timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
	// Exact-PID shell must refuse independently corrupted start time and run token.
	processes, e := c.scanDump(ctx, locked)
	if e != nil || len(processes) != 1 {
		t.Fatal(processes, e)
	}
	wrong := processes[0]
	wrong.start = "1"
	if e = c.signalDump(ctx, locked, wrong, "TERM"); e == nil {
		t.Fatal("wrong start time signaled")
	}
	wrongRun := locked
	wrongRun.RunID = "bakabel_wrong_0123456789abcdef"
	if e = c.signalDump(ctx, wrongRun, processes[0], "TERM"); e == nil {
		t.Fatal("wrong token signaled")
	}
	if e = worker.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	worker.Wait()
	active, e := c.PollExec(ctx, locked.ExecID)
	if e != nil || !active.Running {
		t.Fatal("worker death incorrectly treated as source death", active, e)
	}
	// Fresh client reads only the persisted export identity, as scheduler recovery does.
	raw, e := os.ReadFile(lockedFile)
	if e != nil {
		t.Fatal(e)
	}
	var recovered Dump
	if e = json.Unmarshal(raw, &recovered); e != nil {
		t.Fatal(e)
	}
	fresh, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	unknown := recovered
	unknown.ExecID = strings.Repeat("0", 64)
	if _, e = fresh.CancelDump(ctx, unknown); !errors.Is(e, ErrQuarantine) {
		t.Fatal("real unknown exec did not quarantine", e)
	}
	disconnected, e := NewClient(filepath.Join(dir, "disconnected.sock"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = disconnected.CancelDump(ctx, recovered); !errors.Is(e, ErrQuarantine) {
		t.Fatal("disconnected Engine did not quarantine", e)
	}
	stillRunning, e := fresh.PollExec(ctx, recovered.ExecID)
	if e != nil || !stillRunning.Running {
		t.Fatal("quarantine affected live export", stillRunning, e)
	}
	proof, e := fresh.CancelDump(ctx, recovered)
	if e != nil || !proof.NoProcesses || !proof.NoSessions || proof.ExecExitCode == nil {
		t.Fatal("cancellation proof", proof, e)
	}
	t.Logf("locked worker SIGKILL exec=%s exit=%d processes=0 sessions=0 wrong-start=refused wrong-token=refused", locked.ExecID, *proof.ExecExitCode)
	// SIGSTOP a separately owned fixture pg_dump after validating its exact
	// identity. It cannot handle pending TERM, so real cancellation must exercise
	// the independently revalidated KILL escalation rather than merely time out.
	stoppedFile := filepath.Join(dir, "stopped.json")
	stopped, e := c.CreateDump(ctx, p, "bakabel_escalate_0123456789abcdef", persist(stoppedFile))
	if e != nil {
		t.Fatal(e)
	}
	stoppedHelper := launch(stoppedFile, io.Discard)
	defer func() {
		if stoppedHelper.ProcessState == nil {
			stoppedHelper.Process.Kill()
			stoppedHelper.Wait()
		}
	}()
	for {
		rows, queryErr := c.sql(ctx, p, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+stopped.RunID+"' AND wait_event_type='Lock'")
		if queryErr == nil && strings.TrimSpace(string(rows)) == "1" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("escalation lock wait", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	toStop, e := c.scanDump(ctx, stopped)
	if e != nil || len(toStop) != 1 {
		t.Fatal("escalation process identity", toStop, e)
	}
	stopScript := strings.Replace(cancelScript, "TERM|KILL", "STOP", 1)
	if _, e = c.control(ctx, stopped.Source, []string{"sh", "-c", stopScript, "bakabel-fixture-stop", toStop[0].pid, toStop[0].start, stopped.RunID, "STOP"}); e != nil {
		t.Fatal("fixture stop", e)
	}
	escalated, e := fresh.CancelDump(ctx, stopped)
	if e != nil || escalated.ExecExitCode == nil || *escalated.ExecExitCode != 137 || !escalated.NoProcesses || !escalated.NoSessions {
		t.Fatal("KILL escalation proof", escalated, e)
	}
	if e = stoppedHelper.Wait(); e == nil {
		t.Fatal("killed dump helper returned success")
	}
	t.Logf("real TERM-to-KILL escalation exec=%s exit=%d processes=0 sessions=0", stopped.ExecID, *escalated.ExecExitCode)
	if _, e = c.sql(ctx, p, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='"+lockToken+"'"); e != nil {
		t.Fatal(e)
	}
	if _, e = c.WaitExec(ctx, lockID); e != nil {
		t.Fatal(e)
	}
	final, e := c.InspectContainer(ctx, s.ContainerID)
	if e != nil || !final.State.Running || final.State.StartedAt != s.StartedAt || final.RestartCount != 0 {
		t.Fatal("source restarted", final.State, e)
	}
	t.Logf("final source running=%v started=%s restarts=%d; cleanup exact fixture ID only", final.State.Running, final.State.StartedAt, final.RestartCount)
}
