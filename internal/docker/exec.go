package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ExecOptions configures a container exec invocation.
type ExecOptions struct {
	User         string
	Cmd          []string
	Env          []string
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
}

// ExecResult holds bounded output and exit code from Exec.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

type execInspect struct {
	Running  bool `json:"Running"`
	ExitCode *int `json:"ExitCode"`
}

// Demux reads Docker multiplexed non-TTY frames and routes stdout/stderr with backpressure.
func Demux(r io.Reader, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	var hdr [8]byte
	var buf [32 * 1024]byte
	for {
		_, err := io.ReadFull(r, hdr[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("truncated docker stream header: %w", err)
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if (hdr[0] != 1 && hdr[0] != 2) || hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 || n > 1<<24 {
			return errors.New("invalid docker multiplexed stream frame")
		}
		dst := stdout
		if hdr[0] == 2 {
			dst = stderr
		}
		for n > 0 {
			chunk := min(n, int64(len(buf)))
			got, err := io.ReadFull(r, buf[:chunk])
			if err != nil {
				return fmt.Errorf("truncated docker stream payload: %w", err)
			}
			written, err := dst.Write(buf[:got])
			if err != nil || written != got {
				return fmt.Errorf("write docker stream output: %w", err)
			}
			n -= int64(got)
		}
	}
}

func (c *Client) createExec(ctx context.Context, containerID string, opts ExecOptions) (string, error) {
	payload := map[string]any{
		"User":         opts.User,
		"Cmd":          opts.Cmd,
		"Env":          opts.Env,
		"AttachStdin":  opts.AttachStdin,
		"AttachStdout": opts.AttachStdout,
		"AttachStderr": opts.AttachStderr,
		"Tty":          false,
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := c.request(ctx, http.MethodPost, "/containers/"+containerID+"/exec", payload, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("docker exec returned empty ID")
	}
	return out.ID, nil
}

func (c *Client) waitExec(ctx context.Context, execID string) (int, error) {
	for {
		var st execInspect
		if err := c.request(ctx, http.MethodGet, "/exec/"+execID+"/json", nil, &st); err != nil {
			return -1, err
		}
		if !st.Running {
			if st.ExitCode == nil {
				return -1, errors.New("docker exec completed without exit code")
			}
			return *st.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Exec runs a short command inside containerID and captures bounded stdout/stderr.
func (c *Client) Exec(ctx context.Context, containerID string, opts ExecOptions) (ExecResult, error) {
	var stdout, stderr limitedBuffer
	stdout.limit = 64 * 1024
	stderr.limit = 64 * 1024
	code, err := c.StreamExecOut(ctx, containerID, opts, &stdout, &stderr)
	return ExecResult{ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String()}, err
}

// StreamExecOut executes a command inside containerID and streams stdout/stderr.
func (c *Client) StreamExecOut(ctx context.Context, containerID string, opts ExecOptions, stdout, stderr io.Writer) (int, error) {
	opts.AttachStdin = false
	opts.AttachStdout = true
	opts.AttachStderr = true
	execID, err := c.createExec(ctx, containerID, opts)
	if err != nil {
		return -1, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return -1, fmt.Errorf("dial docker socket for exec: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, _ := http.NewRequest(http.MethodPost, "http://docker"+c.prefix(ctx)+"/exec/"+execID+"/start", bytes.NewBufferString(`{"Detach":false,"Tty":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		return -1, fmt.Errorf("write docker exec start: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return -1, fmt.Errorf("read docker exec start response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		return -1, APIError{StatusCode: resp.StatusCode}
	}
	_ = conn.SetDeadline(time.Time{})

	var stream io.Reader = resp.Body
	if resp.StatusCode == http.StatusSwitchingProtocols {
		stream = br
	}
	demuxErr := Demux(stream, stdout, stderr)
	code, waitErr := c.waitExec(ctx, execID)
	if demuxErr != nil {
		return code, demuxErr
	}
	return code, waitErr
}

// StreamExecIn executes a command inside containerID, streaming stdin into it via TCP upgrade.
func (c *Client) StreamExecIn(ctx context.Context, containerID string, opts ExecOptions, stdin io.Reader, stderr io.Writer) (int, error) {
	opts.AttachStdin = true
	opts.AttachStdout = true
	opts.AttachStderr = true
	execID, err := c.createExec(ctx, containerID, opts)
	if err != nil {
		return -1, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if err != nil {
		return -1, fmt.Errorf("dial docker socket for exec stdin: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, _ := http.NewRequest(http.MethodPost, "http://docker"+c.prefix(ctx)+"/exec/"+execID+"/start", bytes.NewBufferString(`{"Detach":false,"Tty":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		return -1, fmt.Errorf("write docker exec stdin start: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return -1, fmt.Errorf("read docker exec stdin response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return -1, fmt.Errorf("docker exec stdin requires HTTP 101 upgrade, got %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})

	sendErrCh := make(chan error, 1)
	go func() {
		var buf [32 * 1024]byte
		_, copyErr := io.CopyBuffer(conn, stdin, buf[:])
		if copyErr == nil {
			if uc, ok := conn.(*net.UnixConn); ok {
				copyErr = uc.CloseWrite()
			}
		}
		if copyErr != nil {
			_ = conn.Close()
		}
		sendErrCh <- copyErr
	}()

	demuxErr := Demux(br, io.Discard, stderr)
	if demuxErr != nil {
		_ = conn.Close()
	}
	sendErr := <-sendErrCh

	code, waitErr := c.waitExec(ctx, execID)
	if sendErr != nil {
		return code, fmt.Errorf("stream stdin to container: %w", sendErr)
	}
	if demuxErr != nil {
		return code, demuxErr
	}
	return code, waitErr
}

// DumpCompletionPrefix marks the end of a verified pg_dump stdout stream.
const DumpCompletionPrefix = "\x00BAKABEL_DONE:"

// DumpStream forwards pg_dump bytes while verifying the PGDMP header and trailing
// completion marker so a dropped Docker stream cannot silently truncate a backup.
type DumpStream struct {
	out    io.Writer
	marker []byte
	tail   []byte
	header []byte
	err    error
}

// NewDumpStream returns a DumpStream that strips the completion marker for runID.
func NewDumpStream(out io.Writer, runID string) *DumpStream {
	marker := []byte(DumpCompletionPrefix + runID + "\x00")
	return &DumpStream{
		out:    out,
		marker: marker,
		tail:   make([]byte, 0, len(marker)),
		header: make([]byte, 0, 5),
	}
}

func (s *DumpStream) forward(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	n, err := s.out.Write(p)
	if err != nil || n != len(p) {
		return errors.New("backup archive sink write failed")
	}
	if len(s.header) < 5 {
		s.header = append(s.header, p[:min(len(p), 5-len(s.header))]...)
	}
	return nil
}

// Write implements io.Writer.
func (s *DumpStream) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	excess := len(s.tail) + len(p) - len(s.marker)
	if excess <= 0 {
		s.tail = append(s.tail, p...)
		return len(p), nil
	}
	if excess <= len(s.tail) {
		if err := s.forward(s.tail[:excess]); err != nil {
			s.err = err
			return 0, err
		}
		copy(s.tail, s.tail[excess:])
		s.tail = append(s.tail[:len(s.tail)-excess], p...)
	} else {
		if err := s.forward(s.tail); err != nil {
			s.err = err
			return 0, err
		}
		if err := s.forward(p[:excess-len(s.tail)]); err != nil {
			s.err = err
			return 0, err
		}
		s.tail = append(s.tail[:0], p[len(p)-len(s.marker):]...)
	}
	return len(p), nil
}

// Finish validates both the PostgreSQL custom-archive header and completion sentinel.
func (s *DumpStream) Finish() error {
	if s.err != nil {
		return s.err
	}
	if !bytes.Equal(s.header, []byte("PGDMP")) {
		return errors.New("pg_dump output missing PGDMP archive header")
	}
	if !bytes.Equal(s.tail, s.marker) {
		return errors.New("pg_dump stream truncated before completion marker")
	}
	return nil
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remain := b.limit - b.buf.Len()
	if remain > 0 {
		take := min(len(p), remain)
		_, _ = b.buf.Write(p[:take])
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
