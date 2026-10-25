package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Demux applies backpressure and uses one 32KiB buffer regardless of frame length.
// Neither stream is retained; callers must bound and redact diagnostic sinks.
func Demux(r io.Reader, stdout, stderr io.Writer) error {
	if stdout == nil || stderr == nil {
		return errors.New("stream sinks required")
	}
	var header [8]byte
	var buf [32 * 1024]byte
	for {
		_, e := io.ReadFull(r, header[:])
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return errors.New("truncated Docker stream header")
		}
		n := int64(binary.BigEndian.Uint32(header[4:]))
		if (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 || n > 1<<24 {
			return errors.New("invalid Docker stream frame")
		}
		w := stdout
		if header[0] == 2 {
			w = stderr
		}
		for n > 0 {
			take := min(n, int64(len(buf)))
			got, e := io.ReadFull(r, buf[:take])
			if e != nil {
				return errors.New("truncated Docker stream payload")
			}
			written, e := w.Write(buf[:got])
			if e != nil || written != got {
				return errors.New("Docker stream sink failed")
			}
			n -= int64(got)
		}
	}
}

type ExecConfig struct {
	User                                         string
	Cmd, Env                                     []string
	AttachStdout, AttachStderr, AttachStdin, Tty bool
}

func (c *Client) CreateExec(ctx context.Context, container string, cfg ExecConfig) (string, error) {
	if !validID(container) || len(cfg.Cmd) == 0 || cfg.Tty || cfg.AttachStdin {
		return "", ErrQuarantine
	}
	cfg.AttachStdout = true
	cfg.AttachStderr = true
	var out struct {
		ID string `json:"Id"`
	}
	e := c.request(ctx, "POST", "/containers/"+container+"/exec", cfg, &out)
	if e != nil {
		return "", e
	}
	if !validID(out.ID) {
		return "", ErrQuarantine
	}
	return out.ID, nil
}

// StartExec starts an already durably recorded exec. Disconnect is never proof of termination.
func (c *Client) StartExec(ctx context.Context, id string, stdout, stderr io.Writer) error {
	if !validID(id) || stdout == nil || stderr == nil {
		return ErrQuarantine
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", c.socket)
	if e != nil {
		return errors.New("Docker exec connection unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	req, _ := http.NewRequest("POST", "http://docker/v1.55/exec/"+id+"/start", bytes.NewBufferString(`{"Detach":false,"Tty":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if e = req.Write(conn); e != nil {
		return errors.New("Docker exec start unavailable")
	}
	br := bufio.NewReader(conn)
	resp, e := http.ReadResponse(br, req)
	if e != nil {
		return errors.New("Docker exec start response unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 && resp.StatusCode != 200 {
		return apiError(resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	var r io.Reader = resp.Body
	if resp.StatusCode == 101 {
		r = br
	}
	return Demux(r, stdout, stderr)
}

type ExecStatus struct {
	ID, ContainerID string
	Running         bool
	ExitCode        *int
	Pid             int
	ProcessConfig   struct {
		Entrypoint string   `json:"entrypoint"`
		Arguments  []string `json:"arguments"`
	}
}

func (c *Client) PollExec(ctx context.Context, id string) (ExecStatus, error) {
	var s ExecStatus
	if !validID(id) {
		return s, ErrQuarantine
	}
	wire := struct {
		*ExecStatus
		Running *bool
	}{ExecStatus: &s}
	if e := c.request(ctx, "GET", "/exec/"+id+"/json", nil, &wire); e != nil || s.ID != id || s.ContainerID == "" || wire.Running == nil {
		return s, ErrQuarantine
	}
	s.Running = *wire.Running
	return s, nil
}
func (c *Client) WaitExec(ctx context.Context, id string) (int, error) {
	for {
		s, e := c.PollExec(ctx, id)
		if e != nil {
			return 0, ErrQuarantine
		}
		if !s.Running {
			if s.ExitCode == nil || *s.ExitCode < 0 || *s.ExitCode > 255 {
				return 0, ErrQuarantine
			}
			return *s.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return 0, ErrQuarantine
		case <-time.After(100 * time.Millisecond):
		}
	}
}
