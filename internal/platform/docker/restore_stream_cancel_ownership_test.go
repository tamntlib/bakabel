package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The caller holds a real io.Pipe writer open. Observing Read and Close does not
// release it: only caller cancellation (or failure cleanup) may abort this input.
type cancelOwnershipInput struct {
	*io.PipeReader
	reading, closed     chan struct{}
	readOnce, closeOnce sync.Once
}

func (p *cancelOwnershipInput) Read(b []byte) (int, error) {
	p.readOnce.Do(func() { close(p.reading) })
	return p.PipeReader.Read(b)
}

func (p *cancelOwnershipInput) Close() error {
	err := p.PipeReader.Close()
	p.closeOnce.Do(func() { close(p.closed) })
	return err
}

// Synthetic Engine only: the importer is already terminal at output EOF. This
// exercises the real Unix/API ownership boundary, NOT native TERM/KILL or PG.
func cancelOwnershipEngine(t *testing.T, input *cancelOwnershipInput, unknown bool) (*Client, RestoreExec, <-chan struct{}) {
	t.Helper()
	d := RestoreExec{Target: Source{"daemon", "target", "start"}, ExecID: "ownership", RunID: "restore_ownership_0123456789", Database: "db", User: "postgres"}
	args, err := restoreArgs(d)
	if err != nil {
		t.Fatal(err)
	}
	var terminal atomic.Bool
	var control atomic.Value
	control.Store("")
	outputEOF := make(chan struct{})
	peerStarted := make(chan struct{})
	peerDone := make(chan error, 1)
	var scans, sessions atomic.Int32
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/info":
			io.WriteString(w, `{"ID":"daemon"}`)
		case "/v1.55/containers/target/json":
			io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"},"RestartCount":0}`)
		case "/v1.55/exec/ownership/json":
			var exit *int
			if terminal.Load() && !unknown {
				code := 137
				exit = &code
			}
			json.NewEncoder(w).Encode(map[string]any{"ID": d.ExecID, "ContainerID": "target", "Running": false, "Pid": 0, "ExitCode": exit, "ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": args}})
		case "/v1.55/containers/target/exec":
			var cfg ExecConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			switch {
			case reflect.DeepEqual(cfg.Cmd, []string{"sh", "-c", scanScript, "bakabel-restore-scan", d.RunID}):
				scans.Add(1)
				control.Store("") // no correlated processes
			case len(cfg.Cmd) > 0 && cfg.Cmd[0] == "/usr/local/bin/psql" && strings.Contains(cfg.Cmd[len(cfg.Cmd)-1], "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+d.RunID+"'"):
				sessions.Add(1)
				control.Store("0\n")
			default:
				t.Error("unexpected control operation (synthetic fixture must not signal)")
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"Id":"control"}`)
		case "/v1.55/exec/control/start":
			w.Write(frame(1, control.Load().(string)))
		case "/v1.55/exec/control/json":
			io.WriteString(w, `{"ID":"control","ContainerID":"target","Running":false,"Pid":0,"ExitCode":0}`)
		case "/v1.55/exec/ownership/start":
			close(peerStarted)
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			conn, br, err := w.(http.Hijacker).Hijack()
			if err != nil {
				peerDone <- err
				return
			}
			defer func() { conn.Close(); peerDone <- err }()
			if _, err = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"); err != nil {
				return
			}
			// Wait until the real sender is blocked on the caller-owned pipe;
			// failure cleanup must also release a peer whose sender never started.
			select {
			case <-input.reading:
			case <-input.closed:
				return
			}
			terminal.Store(true)
			if err = conn.(*net.UnixConn).CloseWrite(); err != nil {
				return
			}
			close(outputEOF)                 // valid demux EOF, NOT producer EOF
			_, err = io.Copy(io.Discard, br) // caller must close its transport
		default:
			t.Errorf("unexpected API path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	c, err := NewClient(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		clean, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(clean); err != nil {
			srv.Close()
			t.Error("API shutdown", err)
		}
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			t.Error("API serve join", err)
		}
		select {
		case <-peerStarted:
			select {
			case err := <-peerDone:
				if err != nil {
					t.Error("stream peer join", err)
				}
			case <-clean.Done():
				t.Error("stream peer did not join")
			}
		default:
		}
		if !unknown && (scans.Load() < 2 || sessions.Load() < 1) {
			t.Error("remote proof did not independently scan processes and sessions")
		}
	})
	return c, d, outputEOF
}

func cancelOwnershipAwait(t *testing.T, ctx context.Context, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("ownership barrier", ctx.Err())
	}
}

func cancelOwnershipCase(t *testing.T, fresh, unknown bool) {
	t.Helper()
	reader, writer := io.Pipe()
	input := &cancelOwnershipInput{PipeReader: reader, reading: make(chan struct{}), closed: make(chan struct{})}
	t.Cleanup(func() { writer.Close(); input.Close() })
	c, d, outputEOF := cancelOwnershipEngine(t, input, unknown)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	streamCtx, streamCancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	var streamErr error
	go func() { _, streamErr = c.StreamRestoreExec(streamCtx, d, input); close(finished) }()
	// Always release local resources, including on a failed remote proof. Cleanup
	// is not evidence that the remote importer or session actually terminated.
	t.Cleanup(func() {
		streamCancel()
		writer.Close()
		input.Close()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("owned stream goroutine did not join")
		}
	})
	cancelOwnershipAwait(t, ctx, input.reading)
	cancelOwnershipAwait(t, ctx, outputEOF)
	remote := c
	if fresh {
		var err error
		remote, err = NewClient(c.socket)
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Close()
		if remote == c || remote.http == c.http {
			t.Fatal("remote proof client is not independent")
		}
	}
	proof, err := remote.CancelRestoreExec(ctx, d)
	if unknown {
		if !errors.Is(err, ErrQuarantine) || proof.ExecExitCode != nil || proof.SourceTerminal || proof.ExecNeverStarted || proof.NoProcesses || proof.NoSessions {
			t.Fatalf("unknown remote outcome must retain quarantine: %+v %v", proof, err)
		}
	} else if err != nil || proof.ExecExitCode == nil || *proof.ExecExitCode != 137 || !proof.NoProcesses || !proof.NoSessions {
		t.Fatalf("independent remote terminal proof: %+v %v", proof, err)
	}
	// These checks occur while the producer remains held, BEFORE any release;
	// there is no post-release select-winner oracle. Remote proof is not EOF.
	select {
	case <-input.closed:
		t.Fatal("remote proof closed caller input")
	default:
	}
	select {
	case <-finished:
		t.Fatal("stream joined without caller-owned abort")
	default:
	}
	if streamCtx.Err() != nil || ctx.Err() != nil {
		t.Fatal("remote proof consumed local/outer deadline")
	}
	// Proof-before-local-abort is specific to this independent-proof regression,
	// not a universal API order: production failure unwind cancels locally first.
	streamCancel()
	cancelOwnershipAwait(t, ctx, finished)
	if streamErr == nil || !errors.Is(streamErr, context.Canceled) || ctx.Err() != nil {
		t.Fatalf("local abort must join with error while outer context lives: %v outer=%v", streamErr, ctx.Err())
	}
	cancelOwnershipAwait(t, ctx, input.closed)
	if unknown {
		// Local cleanup must not turn an unknown remote result into terminal proof.
		proof, err = remote.CancelRestoreExec(ctx, d)
		if !errors.Is(err, ErrQuarantine) || proof.ExecExitCode != nil || proof.NoProcesses || proof.NoSessions || proof.SourceTerminal || proof.ExecNeverStarted {
			t.Fatalf("local abort substituted for remote proof: %+v %v", proof, err)
		}
	}
}

func TestRestoreStreamCancelOwnership(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		name := "same_client"
		if fresh {
			name = "fresh_client"
		}
		t.Run(name, func(t *testing.T) { cancelOwnershipCase(t, fresh, false) })
	}
}

func TestRestoreStreamCancelOwnershipUnknownProof(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		name := "same_client"
		if fresh {
			name = "fresh_client"
		}
		t.Run(name, func(t *testing.T) { cancelOwnershipCase(t, fresh, true) })
	}
}
