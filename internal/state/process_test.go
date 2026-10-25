package state

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The child is a real separate launcher process, not a goroutine sharing Go state.
func TestStateSubprocess(t *testing.T) {
	mode := os.Getenv("BAKABEL_STATE_TEST")
	if mode == "" {
		return
	}
	o, e := Acquire(os.Getenv("BAKABEL_STATE_DIR"))
	if mode == "busy" {
		if !errors.Is(e, ErrBusy) {
			fmt.Fprintf(os.Stderr, "expected busy: %v", e)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if e != nil {
		fmt.Fprint(os.Stderr, e)
		os.Exit(1)
	}
	defer o.Close()
	if mode == "pending" {
		real := o.rename
		o.rename = func(a int, b string, c int, d string) error {
			fmt.Println("ready")
			var one [1]byte
			os.Stdin.Read(one[:])
			return real(a, b, c, d)
		}
		if e = o.NewRun(initial()); e != nil {
			t.Fatal(e)
		}
		return
	}
	if e = o.NewRun(initial()); e != nil {
		t.Fatal(e)
	}
	r := initial()
	phase := Phase(os.Getenv("BAKABEL_STATE_PHASE"))
	if phase == PhaseCreatingExec || phase == PhaseExecCreated || phase == PhaseExecStarted {
		r.SourceContainerID = "exact-source"
		r.SourceStartedAt = "2026-10-25T00:00:00Z"
		r.Phase = PhaseCreatingExec
		if e = o.Save(r); e != nil {
			t.Fatal(e)
		}
		if phase != PhaseCreatingExec {
			r.ExecID = "exact-exec"
			r.Phase = PhaseExecCreated
			if e = o.Save(r); e != nil {
				t.Fatal(e)
			}
		}
		if phase == PhaseExecStarted {
			r.Phase = phase
			if e = o.Save(r); e != nil {
				t.Fatal(e)
			}
		}
	}
	if phase == PhaseQuarantine {
		r.Phase = phase
		r.Status = StatusBlocked
		if e = o.Save(r); e != nil {
			t.Fatal(e)
		}
	}
	fmt.Println("ready")
	var b [1]byte
	os.Stdin.Read(b[:])
}

type child struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	cancel context.CancelFunc
	waited bool
}

func launch(t *testing.T, mode, dir, phase, run string) *child {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStateSubprocess$")
	cmd.Env = append(os.Environ(), "BAKABEL_STATE_TEST="+mode, "BAKABEL_STATE_DIR="+dir, "BAKABEL_STATE_PHASE="+phase, "BAKABEL_STATE_RUN="+run)
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		cancel()
		t.Fatal(e)
	}
	c := &child{cmd: cmd, input: in, output: bufio.NewReader(out), cancel: cancel}
	t.Cleanup(func() {
		in.Close()
		if !c.waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
		cancel()
	})
	return c
}
func (c *child) ready(t *testing.T) {
	t.Helper()
	line, e := c.output.ReadString('\n')
	if e != nil || line != "ready\n" {
		t.Fatalf("child not ready: %q %v", line, e)
	}
}
func (c *child) wait() error { e := c.cmd.Wait(); c.waited = true; c.cancel(); return e }

func TestCrossProcessGuardContention(t *testing.T) {
	dir := t.TempDir()
	holder := launch(t, "hold", dir, "intent", "")
	holder.ready(t)
	contender := launch(t, "busy", dir, "", "")
	if e := contender.wait(); e != nil {
		t.Fatal(e)
	}
	holder.input.Close()
	if e := holder.wait(); e != nil {
		t.Fatal(e)
	}
}

func TestKilledLauncherOwnershipPersistsAtEveryPhase(t *testing.T) {
	for _, phase := range []Phase{PhaseIntent, PhaseCreatingExec, PhaseExecCreated, PhaseExecStarted, PhaseQuarantine} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			c := launch(t, "hold", dir, string(phase), "")
			c.ready(t)
			if e := c.cmd.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e := c.wait(); e == nil {
				t.Fatal("SIGKILL child exited successfully")
			}
			o, e := Acquire(dir)
			if e != nil {
				t.Fatalf("kernel guard not reacquirable: %v", e)
			}
			defer o.Close()
			r, e := o.Load()
			if e != nil || r.Phase != phase {
				t.Fatalf("durable ownership lost: %#v %v", r, e)
			}
			next := initial()
			next.RunID = "new-run"
			if e = o.NewRun(next); !errors.Is(e, ErrOwned) {
				t.Fatalf("new run admitted after SIGKILL: %v", e)
			}
		})
	}
}

func TestKilledWriteLeavesBoundedFailClosedPending(t *testing.T) {
	dir := t.TempDir()
	c := launch(t, "pending", dir, "", "")
	c.ready(t)
	c.cmd.Process.Kill()
	c.wait()
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if _, e = o.Load(); !errors.Is(e, ErrNoRun) {
		t.Fatalf("pre-rename owner unexpectedly visible: %v", e)
	}
	if e = o.NewRun(initial()); e == nil {
		t.Fatal("orphan pending silently reused")
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 2 {
		t.Fatalf("unbounded or removed residue: %v", entries)
	}
}

func TestConcurrentProcessesElectOneDurableOwner(t *testing.T) {
	// All six children synchronize BEFORE Acquire, so no child is favored by startup order.
	dir := t.TempDir()
	var children []*exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var inputs []io.WriteCloser
	var outputs []*bufio.Reader
	for i := 0; i < 6; i++ {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRaceBarrierSubprocess$")
		cmd.Env = append(os.Environ(), "BAKABEL_STATE_TEST=barrier", "BAKABEL_STATE_DIR="+dir, fmt.Sprintf("BAKABEL_STATE_RUN=run-%d", i))
		in, _ := cmd.StdinPipe()
		out, _ := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		children = append(children, cmd)
		inputs = append(inputs, in)
		outputs = append(outputs, bufio.NewReader(out))
	}
	t.Cleanup(func() {
		for _, cmd := range children {
			if cmd.ProcessState == nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		}
	})
	for _, out := range outputs {
		line, e := out.ReadString('\n')
		if e != nil || line != "ready\n" {
			t.Fatalf("barrier: %q %v", line, e)
		}
	}
	for _, in := range inputs {
		in.Write([]byte("x"))
		in.Close()
	}
	wins := 0
	for i, cmd := range children {
		b, _ := io.ReadAll(outputs[i])
		e := cmd.Wait()
		if e == nil {
			if !strings.Contains(string(b), "won") {
				t.Fatal("winner had no receipt")
			}
			wins++
		} else {
			var ex *exec.ExitError
			if !errors.As(e, &ex) || (ex.ExitCode() != 2 && ex.ExitCode() != 3) {
				t.Fatal(e)
			}
		}
	}
	if wins != 1 {
		t.Fatalf("durable winners: %d", wins)
	}
	o, e := Acquire(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	if _, e = o.Load(); e != nil {
		t.Fatal(e)
	}
}
func TestRaceBarrierSubprocess(t *testing.T) {
	if os.Getenv("BAKABEL_STATE_TEST") != "barrier" {
		return
	}
	fmt.Println("ready")
	var b [1]byte
	os.Stdin.Read(b[:])
	o, e := Acquire(os.Getenv("BAKABEL_STATE_DIR"))
	if errors.Is(e, ErrBusy) {
		os.Exit(2)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	r := initial()
	r.RunID = os.Getenv("BAKABEL_STATE_RUN")
	e = o.NewRun(r)
	if errors.Is(e, ErrOwned) {
		os.Exit(3)
	}
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("won")
}
