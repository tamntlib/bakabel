// Package docker implements a deliberately small Docker Engine Unix-socket adapter.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var ErrQuarantine = errors.New("docker ownership quarantined: terminal identity not proven")

type Client struct {
	socket string
	http   *http.Client
}
type apiError int

func (e apiError) Error() string { return fmt.Sprintf("docker API status %d", int(e)) }
func NewClient(socket string) (*Client, error) {
	if !strings.HasPrefix(socket, "/") {
		return nil, errors.New("absolute Docker socket required")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	return &Client{socket: socket, http: &http.Client{Transport: tr}}, nil
}

// Close releases this client's idle HTTP connections. Active request/exec
// lifetimes remain governed by their contexts and explicit stream closure.
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) request(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return errors.New("docker request encoding failed")
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://docker/v1.55"+path, body)
	if e != nil {
		return errors.New("invalid Docker request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(req)
	if e != nil {
		return errors.New("docker request unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiError(resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	// Control responses only. Streaming goes through StartExec, never this decoder.
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); e != nil {
		return errors.New("invalid Docker response")
	}
	return nil
}
func validID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

type DaemonInfo struct {
	ID    string
	Swarm struct {
		NodeID           string
		ControlAvailable bool
	}
}

func (c *Client) Info(ctx context.Context) (DaemonInfo, error) {
	var v DaemonInfo
	e := c.request(ctx, "GET", "/info", nil, &v)
	if e == nil && v.ID == "" {
		e = ErrQuarantine
	}
	return v, e
}

type Container struct {
	ID    string `json:"Id"`
	State struct {
		Running   bool
		StartedAt string
		Pid       int
	}
	Config struct {
		Env    []string
		Labels map[string]string
	}
	Mounts       []Mount
	RestartCount int
}
type Mount struct {
	Type, Name, Source, Destination string
	RW                              bool
}

func (c *Client) InspectContainer(ctx context.Context, id string) (Container, error) {
	var v Container
	if !validID(id) {
		return v, ErrQuarantine
	}
	wire := struct {
		*Container
		State *struct {
			Running   *bool
			StartedAt string
			Pid       int
		}
	}{Container: &v}
	e := c.request(ctx, "GET", "/containers/"+id+"/json", nil, &wire)
	if e != nil {
		return v, e
	}
	if v.ID == "" || wire.State == nil || wire.State.Running == nil || wire.State.StartedAt == "" {
		return v, ErrQuarantine
	}
	v.State.Running = *wire.State.Running
	v.State.StartedAt = wire.State.StartedAt
	v.State.Pid = wire.State.Pid
	return v, nil
}

type Source struct{ DaemonID, ContainerID, StartedAt string }
type SourceStatus int

const (
	SourceUnknown SourceStatus = iota
	SourceRunning
	SourceTerminal
)

func (c *Client) CaptureSource(ctx context.Context, id string) (Source, error) {
	d, e := c.Info(ctx)
	if e != nil {
		return Source{}, ErrQuarantine
	}
	v, e := c.InspectContainer(ctx, id)
	if e != nil || !v.State.Running {
		return Source{}, ErrQuarantine
	}
	return Source{d.ID, v.ID, v.State.StartedAt}, nil
}
func (c *Client) CheckSource(ctx context.Context, s Source) (SourceStatus, error) {
	if s.DaemonID == "" || s.ContainerID == "" || s.StartedAt == "" {
		return SourceUnknown, ErrQuarantine
	}
	d, e := c.Info(ctx)
	if e != nil || d.ID != s.DaemonID {
		return SourceUnknown, ErrQuarantine
	}
	v, e := c.InspectContainer(ctx, s.ContainerID)
	if e == apiError(404) {
		return SourceTerminal, nil
	}
	if e != nil || v.ID != s.ContainerID {
		return SourceUnknown, ErrQuarantine
	}
	if !v.State.Running || v.State.StartedAt != s.StartedAt {
		return SourceTerminal, nil
	}
	return SourceRunning, nil
}
