package docker

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// ErrRestoreNotStarted proves this call never issued an exec-start request.
// Only a fenced caller may pair it with VerifyUnstartedRestoreExec; a transport
// failure AFTER start may have been accepted and is deliberately NOT this error.
var ErrRestoreNotStarted = errors.New("restore exec start not issued")

// startRestoreInput is deliberately private: the only stdin-enabled command is
// the fixed pg_restore created above, not a new arbitrary shell/exec interface.
// It reuses the existing bounded, non-TTY demultiplexer, retaining neither dump
// bytes nor raw PostgreSQL diagnostics. Closing input MUST unblock its reader.
func (c *Client) startRestoreInput(ctx context.Context, id string, input io.ReadCloser) error {
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if e != nil {
		return errors.New("Docker restore connection unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { input.Close(); conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, _ := http.NewRequest("POST", "http://docker/v1.55/exec/"+id+"/start", bytes.NewBufferString(`{"Detach":false,"Tty":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if e = req.Write(conn); e != nil {
		return errors.New("Docker restore start unavailable")
	}
	br := bufio.NewReader(conn)
	resp, e := http.ReadResponse(br, req)
	if e != nil {
		return errors.New("Docker restore response unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 {
		return errors.New("Docker restore requires full-duplex upgrade")
	}
	conn.SetDeadline(time.Time{})
	type sendResult struct{ copyErr, closeErr error }
	sent := make(chan sendResult, 1)
	go func() {
		var buf [32 * 1024]byte
		_, copyErr := io.CopyBuffer(conn, input, buf[:])
		var closeErr error
		if copyErr == nil {
			closeErr = conn.(*net.UnixConn).CloseWrite()
		}
		// Either sender failure must wake Demux even if peer output stays open.
		if copyErr != nil || closeErr != nil {
			conn.Close()
		}
		sent <- sendResult{copyErr, closeErr}
	}()
	streamErr := Demux(br, io.Discard, io.Discard)
	// Valid output EOF does not prove the producer has reached its own EOF.
	// Only failed output aborts input; cancellation remains armed through join.
	if streamErr != nil {
		input.Close()
		conn.Close()
	}
	inputErr := <-sent
	input.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var result error
	if streamErr != nil {
		result = errors.New("Docker restore output stream failed")
	}
	if inputErr.copyErr != nil || inputErr.closeErr != nil {
		result = errors.Join(result, errors.New("Docker restore input stream failed"))
	}
	return result
}

// StreamRestoreExec starts only an already persisted checkpoint. The caller MUST
// invoke CancelRestoreExec after any error and retain the checkpoint until a
// terminal proof is returned; disconnect is not proof of process/backend death.
func (c *Client) StreamRestoreExec(ctx context.Context, d RestoreExec, input io.ReadCloser) (int, error) {
	if input == nil {
		return 0, errors.Join(ErrRestoreNotStarted, ErrQuarantine)
	}
	defer input.Close()
	status, e := c.CheckSource(ctx, d.Target)
	if e != nil || status != SourceRunning {
		return 0, errors.Join(ErrRestoreNotStarted, ErrQuarantine, ctx.Err())
	}
	x, e := c.inspectRestoreExec(ctx, d)
	if e != nil || x.Running || x.Pid != 0 || x.ExitCode != nil {
		return 0, errors.Join(ErrRestoreNotStarted, ErrQuarantine, ctx.Err())
	}
	streamErr := c.startRestoreInput(ctx, d.ExecID, input)
	if streamErr != nil {
		// A detached import may be blocked in SQL even after transport failure. Do
		// not wait indefinitely here: return authority to the exact cancellation API.
		state, e := c.inspectRestoreExec(ctx, d)
		if e != nil || state.Running || state.ExitCode == nil || *state.ExitCode < 0 || *state.ExitCode > 255 {
			return 0, errors.Join(streamErr, ErrQuarantine)
		}
		return *state.ExitCode, streamErr
	}
	code, e := c.WaitExec(ctx, d.ExecID)
	if e != nil {
		return 0, errors.Join(streamErr, ErrQuarantine)
	}
	if code != 0 {
		return code, errors.Join(streamErr, errors.New("PostgreSQL import failed"))
	}
	return code, streamErr
}
