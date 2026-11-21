// Package docker provides a minimal zero-dependency Docker Engine Unix-socket client.
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
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// APIError represents a non-2xx HTTP status returned by the Docker daemon.
type APIError struct {
	StatusCode int
	Message    string
}

func (e APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("docker API %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("docker API status %d", e.StatusCode)
}

// Client talks to a local Docker daemon over a Unix socket.
type Client struct {
	socket     string
	http       *http.Client
	httpStream *http.Client
	prefixOnce sync.Once
	apiPrefix  string
}

// NewClient creates a Docker Unix-socket client.
func NewClient(socket string) (*Client, error) {
	if !strings.HasPrefix(socket, "/") {
		return nil, errors.New("docker socket must be an absolute path")
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	tr := &http.Transport{
		DialContext:           dial,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	streamTr := &http.Transport{
		DialContext:         dial,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		socket:     socket,
		http:       &http.Client{Transport: tr},
		httpStream: &http.Client{Transport: streamTr},
	}, nil
}

// Close closes idle transport connections.
func (c *Client) Close() {
	c.http.CloseIdleConnections()
	c.httpStream.CloseIdleConnections()
}

func (c *Client) prefix(ctx context.Context) string {
	c.prefixOnce.Do(func() {
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(pingCtx, http.MethodGet, "http://docker/_ping", nil)
		if err != nil {
			return
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		if v := strings.TrimSpace(resp.Header.Get("Api-Version")); v != "" {
			c.apiPrefix = "/v" + v
		}
	})
	return c.apiPrefix
}

func (c *Client) request(ctx context.Context, method, path string, in, out any) error {
	return c.doRequest(ctx, c.http, method, path, in, out)
}

func (c *Client) requestLong(ctx context.Context, method, path string, in, out any) error {
	return c.doRequest(ctx, c.httpStream, method, path, in, out)
}

func (c *Client) doRequest(ctx context.Context, hc *http.Client, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode docker request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	fullURL := "http://docker" + c.prefix(ctx) + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return fmt.Errorf("build docker request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker request %s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&errBody)
		return APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(errBody.Message)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode docker response for %s %s: %w", method, path, err)
	}
	return nil
}

// DaemonInfo holds basic Docker daemon and Swarm node metadata.
type DaemonInfo struct {
	ID    string `json:"ID"`
	Swarm struct {
		LocalNodeState   string `json:"LocalNodeState"`
		NodeID           string `json:"NodeID"`
		ControlAvailable bool   `json:"ControlAvailable"`
	} `json:"Swarm"`
}

// Info queries GET /info.
func (c *Client) Info(ctx context.Context) (DaemonInfo, error) {
	var info DaemonInfo
	err := c.request(ctx, http.MethodGet, "/info", nil, &info)
	return info, err
}

// Mount represents a container mount point.
type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// ContainerSummary represents a running container from GET /containers/json.
type ContainerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// Container represents detailed container state from GET /containers/<id>/json.
type Container struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Running   bool   `json:"Running"`
		StartedAt string `json:"StartedAt"`
		ExitCode  int    `json:"ExitCode"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []Mount `json:"Mounts"`
}

// ListContainers returns running containers.
func (c *Client) ListContainers(ctx context.Context) ([]ContainerSummary, error) {
	var list []ContainerSummary
	err := c.request(ctx, http.MethodGet, "/containers/json", nil, &list)
	return list, err
}

// InspectContainer returns detailed container metadata.
func (c *Client) InspectContainer(ctx context.Context, idOrName string) (Container, error) {
	var ctr Container
	if strings.TrimSpace(idOrName) == "" {
		return ctr, errors.New("container ID or name is required")
	}
	err := c.request(ctx, http.MethodGet, "/containers/"+url.PathEscape(idOrName)+"/json", nil, &ctr)
	return ctr, err
}

// SwarmService represents a service returned by GET /services.
type SwarmService struct {
	ID   string `json:"ID"`
	Spec struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	} `json:"Spec"`
}

// SwarmTask represents a task returned by GET /tasks.
type SwarmTask struct {
	ID        string `json:"ID"`
	ServiceID string `json:"ServiceID"`
	NodeID    string `json:"NodeID"`
	Status    struct {
		State           string `json:"State"`
		ContainerStatus struct {
			ContainerID string `json:"ContainerID"`
		} `json:"ContainerStatus"`
	} `json:"Status"`
}

// ListServices lists Swarm services.
func (c *Client) ListServices(ctx context.Context) ([]SwarmService, error) {
	var svcs []SwarmService
	err := c.request(ctx, http.MethodGet, "/services", nil, &svcs)
	return svcs, err
}

// ListRunningTasks returns running Swarm tasks for serviceID.
func (c *Client) ListRunningTasks(ctx context.Context, serviceID string) ([]SwarmTask, error) {
	filters, _ := json.Marshal(map[string][]string{
		"service":       {serviceID},
		"desired-state": {"running"},
	})
	var tasks []SwarmTask
	err := c.request(ctx, http.MethodGet, "/tasks?filters="+url.QueryEscape(string(filters)), nil, &tasks)
	if err != nil {
		return nil, err
	}
	var running []SwarmTask
	for _, t := range tasks {
		if t.Status.State == "running" && t.Status.ContainerStatus.ContainerID != "" {
			running = append(running, t)
		}
	}
	return running, nil
}

// Volume represents metadata from GET /volumes/<name>.
type Volume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Options    map[string]string `json:"Options"`
}

// InspectVolume returns metadata for a named Docker volume.
func (c *Client) InspectVolume(ctx context.Context, name string) (Volume, error) {
	var vol Volume
	if strings.TrimSpace(name) == "" {
		return vol, errors.New("volume name is required")
	}
	err := c.request(ctx, http.MethodGet, "/volumes/"+url.PathEscape(name), nil, &vol)
	return vol, err
}

var mountinfoContainerRe = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// SelfContainer resolves the container Bakabel is currently running inside, or nil if running on a host.
func (c *Client) SelfContainer(ctx context.Context) (*Container, error) {
	if host, err := os.Hostname(); err == nil && host != "" {
		if ctr, err := c.InspectContainer(ctx, host); err == nil && ctr.ID != "" {
			return &ctr, nil
		}
	}
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if m := mountinfoContainerRe.FindSubmatch(b); len(m) == 2 {
			if ctr, err := c.InspectContainer(ctx, string(m[1])); err == nil && ctr.ID != "" {
				return &ctr, nil
			}
		}
	}
	return nil, nil
}
