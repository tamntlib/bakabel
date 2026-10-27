package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// These tests use a real Unix full-duplex transport. The producer release is
// controlled independently of startRestoreInput's return, never by that return.
type lifetimeInput struct {
	payload  *bytes.Reader
	terminal error
	reading  chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
	readOnce sync.Once
}

func newLifetimeInput(payload string, terminal error) *lifetimeInput {
	return &lifetimeInput{payload: bytes.NewReader([]byte(payload)), terminal: terminal,
		reading: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
}

func (p *lifetimeInput) Read(b []byte) (int, error) {
	if p.payload.Len() > 0 {
		return p.payload.Read(b)
	}
	p.readOnce.Do(func() { close(p.reading) })
	select {
	case <-p.release:
		return 0, p.terminal
	case <-p.closed:
		return 0, io.ErrClosedPipe
	}
}

func (p *lifetimeInput) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// Observe the input itself, not the arrival order of result and release
// notifications: either notification can be delayed after the event it reports.
// Recording the terminal Read before returning it makes a normal sender join
// happen after this observation. Recording Close before unblocking the reader
// preserves evidence of an abort even if the producer is released later.
// Embedding only io.ReadCloser also keeps io.Copy on the observed Read path.
type lifetimeObservedInput struct {
	io.ReadCloser
	mu                   sync.Mutex
	terminalRead         bool
	closedBeforeTerminal bool
}

func (p *lifetimeObservedInput) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if err != nil {
		p.mu.Lock()
		p.terminalRead = true
		p.mu.Unlock()
	}
	return n, err
}

func (p *lifetimeObservedInput) Close() error {
	p.mu.Lock()
	p.closedBeforeTerminal = p.closedBeforeTerminal || !p.terminalRead
	p.mu.Unlock()
	return p.ReadCloser.Close()
}

func (p *lifetimeObservedInput) assertTerminalBeforeClose(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.terminalRead || p.closedBeforeTerminal {
		t.Fatal("input closed before its terminal Read completed")
	}
}

func lifetimePeer(t *testing.T, serve func(*net.UnixConn, *bufio.Reader) error) (*Client, <-chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restore.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			done <- err
			return
		}
		_, err = io.Copy(io.Discard, req.Body)
		req.Body.Close()
		if err != nil {
			done <- err
			return
		}
		if req.URL.Path != "/v1.55/exec/unit/start" {
			done <- errors.New("unexpected start path")
			return
		}
		if _, err = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"); err != nil {
			done <- err
			return
		}
		done <- serve(conn, br)
	}()
	return &Client{socket: path}, done
}

func lifetimeAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("barrier not reached")
	}
}

func lifetimeResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("stream/peer did not join")
		return nil
	}
}

func lifetimeAfterOutput(t *testing.T, terminal error) {
	t.Helper()
	const payload = "synthetic-archive"
	input := newLifetimeInput(payload, terminal)
	observed := &lifetimeObservedInput{ReadCloser: input}
	outputEOF := make(chan struct{})
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(br, got); err != nil {
			return err
		}
		if string(got) != payload {
			return errors.New("payload mismatch")
		}
		if err := conn.CloseWrite(); err != nil {
			return err
		}
		close(outputEOF)
		_, err := io.Copy(io.Discard, br)
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer input.Close()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", observed) }()
	lifetimeAwait(t, input.reading)
	lifetimeAwait(t, outputEOF)
	// Independent controller: always release after the bounded held interval,
	// whether the method is still running or returned incorrectly. This is not
	// a producer that can succeed only after the method under test returns.
	released := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); close(input.release); close(released) }()
	lifetimeAwait(t, released)
	err := lifetimeResult(t, result)
	if peerErr := lifetimeResult(t, peer); peerErr != nil {
		t.Fatal(peerErr)
	}
	observed.assertTerminalBeforeClose(t)
	if terminal == io.EOF && err != nil {
		t.Fatalf("valid output EOF rejected successful late input EOF: %v", err)
	}
	if terminal != io.EOF && (err == nil || !strings.Contains(err.Error(), "input stream failed")) {
		t.Fatalf("late input failure lost: %v", err)
	}
}

func TestRestoreLifetimeOutputBeforeInputEOF(t *testing.T) {
	lifetimeAfterOutput(t, io.EOF)
}

func TestRestoreLifetimeSenderFailureWakesOpenOutput(t *testing.T) {
	input := newLifetimeInput("", errors.New("private-reader-diagnostic"))
	keepOutputOpen := make(chan struct{})
	var releaseOnce sync.Once
	releaseOutput := func() { releaseOnce.Do(func() { close(keepOutputOpen) }) }
	defer releaseOutput()
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		_, err := io.Copy(io.Discard, br)
		<-keepOutputOpen
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
	lifetimeAwait(t, input.reading)
	close(input.release)
	var err error
	select {
	case err = <-result:
	case <-time.After(250 * time.Millisecond):
		cancel()
		lifetimeResult(t, result)
		t.Fatal("sender failure did not wake Demux while peer output remained open")
	}
	if err == nil || !strings.Contains(err.Error(), "input stream failed") || strings.Contains(err.Error(), "private-reader-diagnostic") || ctx.Err() != nil {
		t.Fatalf("sender failure lost or diagnostic leaked: %v", err)
	}
	releaseOutput()
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLifetimeLateReaderErrorAfterOutputEOF(t *testing.T) {
	lifetimeAfterOutput(t, errors.New("private-late-reader-diagnostic"))
}

func TestRestoreLifetimeMalformedOutputAbortsBlockedInput(t *testing.T) {
	for name, wire := range map[string][]byte{
		"invalid_header":    {3, 0, 0, 0, 0, 0, 0, 0},
		"truncated_header":  {1},
		"truncated_payload": {1, 0, 0, 0, 0, 0, 0, 2, 'x'},
	} {
		t.Run(name, func(t *testing.T) {
			input := newLifetimeInput("", io.EOF)
			c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
				<-input.reading
				if _, err := conn.Write(wire); err != nil {
					return err
				}
				if err := conn.CloseWrite(); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, br)
				return err
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
			err := lifetimeResult(t, result)
			if err == nil || !strings.Contains(err.Error(), "output stream failed") || ctx.Err() != nil {
				t.Fatalf("invalid output did not abort promptly: %v", err)
			}
			select {
			case <-input.closed:
			default:
				t.Fatal("returned without closing blocked input")
			}
			if err := lifetimeResult(t, peer); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreLifetimeCancellationWhileWaitingAfterOutputEOF(t *testing.T) {
	input := newLifetimeInput("", io.EOF)
	outputEOF := make(chan struct{})
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		<-input.reading
		if err := conn.CloseWrite(); err != nil {
			return err
		}
		close(outputEOF)
		_, err := io.Copy(io.Discard, br)
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
	lifetimeAwait(t, outputEOF)
	cancel()
	if err := lifetimeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	select {
	case <-input.closed:
	default:
		t.Fatal("returned without closing blocked input")
	}
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

// The server never consumes stdin after the upgrade. Read 1 is possible; Read 2
// proves a full 32KiB chunk was written. The held interval then allows the small
// Unix receive buffer to fill, with no drain until cancellation has completed.
type lifetimeFlood struct {
	closed       chan struct{}
	progress     chan struct{}
	once         sync.Once
	progressOnce sync.Once
	reads        int
}

func (p *lifetimeFlood) Read(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	p.reads++
	if p.reads >= 2 {
		p.progressOnce.Do(func() { close(p.progress) })
	}
	clear(b)
	return len(b), nil
}
func (p *lifetimeFlood) Close() error { p.once.Do(func() { close(p.closed) }); return nil }

func TestRestoreLifetimeCancellationUnblocksWriteBackpressure(t *testing.T) {
	input := &lifetimeFlood{closed: make(chan struct{}), progress: make(chan struct{})}
	drain := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(drain) }) }
	defer release()
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		if err := conn.SetReadBuffer(1024); err != nil {
			return err
		}
		<-drain
		_, err := io.Copy(io.Discard, br)
		return err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
	lifetimeAwait(t, input.progress)
	// Not a production timeout: a held fixture interval before cancellation.
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := lifetimeResult(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("backpressured cancellation lost: %v", err)
	}
	select {
	case <-input.closed:
	default:
		t.Fatal("cancellation did not close input")
	}
	release()
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLifetimeFullyClosedPeerRejectsPendingInput(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	peerClosed := make(chan struct{})
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		if err := conn.Close(); err != nil {
			return err
		}
		close(peerClosed)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	producer := make(chan error, 1)
	go func() {
		<-peerClosed
		_, err := io.WriteString(writer, "pending-archive")
		writer.CloseWithError(err)
		producer <- err
	}()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
	err := lifetimeResult(t, result)
	if err == nil || !strings.Contains(err.Error(), "input stream failed") || ctx.Err() != nil {
		t.Fatalf("fully closed peer accepted pending input: %v", err)
	}
	if err := lifetimeResult(t, producer); err != nil {
		t.Fatal("producer was closed before data delivery", err)
	}
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

// Establish the actual errno of the fully-closed Unix peer, independently of
// sanitized production errors. No injected errno and no ENOTCONN exception.
func TestRestoreLifetimeNativeFullyClosedPeerENOTCONN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errno.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() { conn, _ := ln.AcceptUnix(); accepted <- conn }()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	other := <-accepted
	if other == nil {
		t.Fatal("peer accept failed")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("full-close EOF control: n=%d err=%v", n, err)
	}
	err = conn.CloseWrite()
	if err == nil {
		t.Skip("native Unix CloseWrite returned nil after peer full-close and read EOF; ENOTCONN half-close unavailable on this kernel")
	}
	if !errors.Is(err, syscall.ENOTCONN) {
		t.Fatalf("unexpected native shutdown error: %v", err)
	}
}

func TestRestoreLifetimeInputENOTCONNRemainsFatal(t *testing.T) {
	// Explicit input errno unit control, not native transport/half-close proof.
	input := newLifetimeInput("", syscall.ENOTCONN)
	close(input.release)
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		_, err := io.Copy(io.Discard, br)
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.startRestoreInput(ctx, "unit", input)
	if err == nil || !strings.Contains(err.Error(), "input stream failed") || ctx.Err() != nil {
		t.Fatalf("ENOTCONN input error ignored: %v", err)
	}
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLifetimeContextDeadlineAfterValidOutputEOF(t *testing.T) {
	input := newLifetimeInput("", io.EOF)
	outputEOF := make(chan struct{})
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		<-input.reading
		if err := conn.CloseWrite(); err != nil {
			return err
		}
		close(outputEOF)
		_, err := io.Copy(io.Discard, br)
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.startRestoreInput(ctx, "unit", input) }()
	lifetimeAwait(t, outputEOF)
	if err := lifetimeResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("did not wait for existing context deadline: %v", err)
	}
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLifetimeInputEOFFirst(t *testing.T) {
	c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
		got, err := io.ReadAll(br)
		if err != nil {
			return err
		}
		if string(got) != "synthetic-archive" {
			return errors.New("payload mismatch")
		}
		if _, err := conn.Write(frame(2, "discarded diagnostic")); err != nil {
			return err
		}
		return conn.CloseWrite()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.startRestoreInput(ctx, "unit", io.NopCloser(strings.NewReader("synthetic-archive"))); err != nil {
		t.Fatal(err)
	}
	if err := lifetimeResult(t, peer); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreLifetimeNativeProducerExitAfterOutputEOF(t *testing.T) {
	for _, code := range []int{0, 9} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			input, writer := io.Pipe()
			observed := &lifetimeObservedInput{ReadCloser: input}
			defer input.Close()
			defer writer.Close()
			controlR, controlW := io.Pipe()
			defer controlR.Close()
			defer controlW.Close()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "printf synthetic-archive; read line; exit "+strconv.Itoa(code))
			cmd.Stdin, cmd.Stdout = controlR, writer
			producer := make(chan error, 1)
			go func() { err := cmd.Run(); writer.CloseWithError(err); producer <- err }()
			outputEOF := make(chan struct{})
			c, peer := lifetimePeer(t, func(conn *net.UnixConn, br *bufio.Reader) error {
				got := make([]byte, len("synthetic-archive"))
				if _, err := io.ReadFull(br, got); err != nil {
					return err
				}
				if string(got) != "synthetic-archive" {
					return errors.New("payload mismatch")
				}
				if err := conn.CloseWrite(); err != nil {
					return err
				}
				close(outputEOF)
				_, err := io.Copy(io.Discard, br)
				return err
			})
			result := make(chan error, 1)
			go func() { result <- c.startRestoreInput(ctx, "unit", observed) }()
			lifetimeAwait(t, outputEOF)
			released := make(chan error, 1)
			go func() {
				time.Sleep(50 * time.Millisecond)
				_, err := io.WriteString(controlW, "release\n")
				controlW.Close()
				released <- err
			}()
			if err := lifetimeResult(t, released); err != nil {
				t.Fatal(err)
			}
			streamErr := lifetimeResult(t, result)
			producerErr := lifetimeResult(t, producer)
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != code {
				t.Fatalf("native producer exit mismatch: %v", producerErr)
			}
			if err := lifetimeResult(t, peer); err != nil {
				t.Fatal(err)
			}
			observed.assertTerminalBeforeClose(t)
			if code == 0 && (producerErr != nil || streamErr != nil) {
				t.Fatalf("successful producer rejected: producer=%v stream=%v", producerErr, streamErr)
			}
			if code != 0 && (producerErr == nil || streamErr == nil || !strings.Contains(streamErr.Error(), "input stream failed")) {
				t.Fatalf("late native failure lost: producer=%v stream=%v", producerErr, streamErr)
			}
		})
	}
}

// A transport success remains insufficient: the unchanged public API must still
// obtain a valid terminal importer status and reject nonzero/missing statuses.
func TestRestoreLifetimeTransportSuccessStillRequiresImporterSuccess(t *testing.T) {
	for _, code := range []int{0, 9, -1, 256, -999} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			d := RestoreExec{Target: Source{"daemon", "target", "start"}, ExecID: "restoreexec", RunID: "restore_token_0123456789", Database: "db", User: "postgres"}
			args, err := restoreArgs(d)
			if err != nil {
				t.Fatal(err)
			}
			var started atomic.Bool
			peerDone := make(chan error, 1)
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					io.WriteString(w, `{"ID":"daemon"}`)
				case "/v1.55/containers/target/json":
					io.WriteString(w, `{"Id":"target","State":{"Running":true,"StartedAt":"start"}}`)
				case "/v1.55/exec/restoreexec/json":
					var exitCode *int
					if started.Load() && code != -999 {
						exitCode = &code
					}
					json.NewEncoder(w).Encode(map[string]any{"ID": "restoreexec", "ContainerID": "target", "Running": false, "Pid": 0, "ExitCode": exitCode,
						"ProcessConfig": map[string]any{"entrypoint": "/usr/local/bin/pg_restore", "arguments": args}})
				case "/v1.55/exec/restoreexec/start":
					started.Store(true)
					_, err := io.Copy(io.Discard, r.Body)
					if err != nil {
						peerDone <- err
						return
					}
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						peerDone <- err
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err = io.WriteString(conn, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"); err != nil {
						peerDone <- err
						return
					}
					got, err := io.ReadAll(rw.Reader)
					if err == nil && string(got) != "synthetic-archive" {
						err = errors.New("payload mismatch")
					}
					if err == nil {
						err = conn.(*net.UnixConn).CloseWrite()
					}
					peerDone <- err
				default:
					w.WriteHeader(404)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			got, err := c.StreamRestoreExec(ctx, d, io.NopCloser(strings.NewReader("synthetic-archive")))
			if code == 0 && (got != 0 || err != nil) {
				t.Fatalf("terminal success rejected: code=%d err=%v", got, err)
			}
			if code != 0 && err == nil {
				t.Fatalf("invalid importer outcome accepted: code=%d", code)
			}
			if code == 9 && got != 9 {
				t.Fatalf("importer failure exit lost: %d %v", got, err)
			}
			if !started.Load() {
				t.Fatal("did not exercise successful stream")
			}
			if err := lifetimeResult(t, peerDone); err != nil {
				t.Fatal(err)
			}
		})
	}
}
