package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRestoreRealExactPIDStartAndKillEscalation(t *testing.T) {
	socket := os.Getenv("BAKABEL_B2_SOCKET")
	if socket == "" {
		t.Skip("explicit disposable Docker fixture opt-in required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	c, e := NewClient(socket)
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("bakabel-b2-pg-exact-cancel-%d", time.Now().UnixNano())
	cfg := map[string]any{"Image": "postgres:18.6-alpine3.24", "Entrypoint": []string{"sh", "-c", "while [ ! -e /tmp/bakabel-b2-ready ]; do sleep 0.1; done; exec docker-entrypoint.sh postgres"}, "Env": []string{"POSTGRES_HOST_AUTH_METHOD=trust", "POSTGRES_DB=postgres", "POSTGRES_USER=postgres"}, "HostConfig": map[string]any{"NetworkMode": "none", "CpusetCpus": "0,1", "NanoCpus": 2000000000}}
	var out struct {
		ID string `json:"Id"`
	}
	if e = c.request(ctx, "POST", "/containers/create?name="+name, cfg, &out); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		clean, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if e := c.request(clean, "DELETE", "/containers/"+out.ID+"?force=true&v=true", nil, nil); e != nil {
			t.Error(e)
		}
		if _, e := c.InspectContainer(clean, out.ID); e != apiError(404) {
			t.Error("cleanup readback", e)
		}
	})
	if e = c.request(ctx, "POST", "/containers/"+out.ID+"/start", nil, nil); e != nil {
		t.Fatal(e)
	}
	target, e := c.CaptureSource(ctx, out.ID)
	if e != nil {
		t.Fatal(e)
	}
	v, e := c.InspectContainer(ctx, out.ID)
	if e != nil {
		t.Fatal(e)
	}
	if raw, e := exec.Command("taskset", "-pc", "0,1", fmt.Sprint(v.State.Pid)).CombinedOutput(); e != nil {
		t.Fatalf("host PID affinity (runner --pid host): %s %v", raw, e)
	}
	if _, e = c.control(ctx, target, []string{"sh", "-c", ": > /tmp/bakabel-b2-ready"}); e != nil {
		t.Fatal(e)
	}
	for i := 0; ; i++ {
		if _, e = c.control(ctx, target, []string{"/usr/local/bin/pg_isready", "-h", "127.0.0.1", "-U", "postgres"}); e == nil {
			break
		}
		if i > 100 {
			t.Fatal("readiness")
		}
		time.Sleep(100 * time.Millisecond)
	}
	p, e := c.PrepareRestorePostgres(ctx, target, "postgres", "postgres")
	if e != nil {
		t.Fatal(e)
	}
	d, e := c.CreateRestoreExec(ctx, p, "restore_exact_pid_0123456789abcdef", func(RestoreExec) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	finished := make(chan error, 1)
	go func() { _, e := c.StreamRestoreExec(streamCtx, d, reader); finished <- e }()
	var processes []dumpProcess
	for {
		state, e := c.PollExec(ctx, d.ExecID)
		if e != nil {
			t.Fatal(e)
		}
		processes, e = c.scanRestore(ctx, d)
		if e != nil {
			t.Fatal(e)
		}
		if state.Running && len(processes) == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	wrong := processes[0]
	wrong.start = "1"
	if e = c.signalRestore(ctx, d, wrong, "TERM"); e == nil {
		t.Fatal("wrong PID start time signaled")
	}
	wrongToken := d
	wrongToken.RunID = "restore_wrong_token_0123456789"
	if e = c.signalRestore(ctx, wrongToken, processes[0], "TERM"); e == nil {
		t.Fatal("wrong run token signaled")
	}
	now, e := c.scanRestore(ctx, d)
	if e != nil || len(now) != 1 || now[0] != processes[0] {
		t.Fatal("refused signal changed process", now, e)
	}
	// STOP is fixture-only, not an exposed production operation. Pending TERM
	// cannot run, forcing independently revalidated exact KILL escalation.
	stopScript := strings.Replace(strings.ReplaceAll(cancelScript, "/usr/local/bin/pg_dump", "/usr/local/bin/pg_restore"), "TERM|KILL", "STOP", 1)
	if _, e = c.control(ctx, target, []string{"sh", "-c", stopScript, "bakabel-b2-stop", processes[0].pid, processes[0].start, d.RunID, "STOP"}); e != nil {
		t.Fatal(e)
	}
	proof, e := c.CancelRestoreExec(ctx, d)
	if e != nil || proof.ExecExitCode == nil || *proof.ExecExitCode != 137 || !proof.NoProcesses || !proof.NoSessions {
		t.Fatal("real KILL escalation", proof, e)
	}
	// Only after independent remote proof, abort this caller's local stream.
	// This ordering preserves the native KILL oracle, not a universal API order.
	streamCancel()
	select {
	case e := <-finished:
		if e == nil {
			t.Fatal("killed importer returned success")
		}
	case <-ctx.Done():
		t.Fatal("stream did not join", ctx.Err())
	}
	if ctx.Err() != nil {
		t.Fatal("outer deadline expired at stream join", ctx.Err())
	}
	final, e := c.InspectContainer(ctx, target.ContainerID)
	if e != nil || !final.State.Running || final.State.StartedAt != target.StartedAt || final.RestartCount != 0 {
		t.Fatal("target container was restarted", final, e)
	}
	t.Logf("container=%s exec=%s PID=%s start=%s wrong-start/token refused; TERM-to-KILL exit=137 processes=0 sessions=0", target.ContainerID, d.ExecID, processes[0].pid, processes[0].start)
}
