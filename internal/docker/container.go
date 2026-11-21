package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HelperMount configures a bind or volume mount on an ephemeral helper container.
type HelperMount struct {
	Type     string `json:"Type"` // "volume" or "bind"
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly,omitempty"`
}

// HelperSpec defines a short-lived helper container for volume backup/restore.
type HelperSpec struct {
	Image       string
	Cmd         []string
	Env         []string
	Mounts      []HelperMount
	NetworkMode string
	Labels      map[string]string
}

// HelperResult holds the exit code and bounded output from a helper container.
type HelperResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// RunHelper creates, starts, waits for, and always removes an ephemeral helper container.
func (c *Client) RunHelper(ctx context.Context, spec HelperSpec) (HelperResult, error) {
	if spec.Image == "" {
		return HelperResult{}, fmt.Errorf("helper container image is required (set BAKABEL_WORKER_IMAGE when running outside Docker)")
	}
	netMode := spec.NetworkMode
	if netMode == "" {
		netMode = "none"
	}

	body := map[string]any{
		"Image":        spec.Image,
		"Cmd":          spec.Cmd,
		"Env":          spec.Env,
		"Labels":       spec.Labels,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          false,
		"HostConfig": map[string]any{
			"NetworkMode": netMode,
			"Mounts":      spec.Mounts,
		},
	}

	var created struct {
		ID string `json:"Id"`
	}
	if err := c.request(ctx, http.MethodPost, "/containers/create", body, &created); err != nil {
		return HelperResult{}, fmt.Errorf("create helper container: %w", err)
	}
	id := created.ID

	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		_ = c.request(cleanCtx, http.MethodDelete, "/containers/"+id+"?force=true", nil, nil)
	}()

	if err := c.request(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil); err != nil {
		return HelperResult{}, fmt.Errorf("start helper container: %w", err)
	}

	// Wait for helper termination; cancel kills container via defer.
	var waitResp struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	waitErr := c.requestLong(ctx, http.MethodPost, "/containers/"+id+"/wait", nil, &waitResp)
	if waitErr != nil {
		return HelperResult{}, fmt.Errorf("wait for helper container: %w", waitErr)
	}

	stdout, stderr, logErr := c.containerLogs(ctx, id)
	res := HelperResult{
		ExitCode: waitResp.StatusCode,
		Stdout:   stdout,
		Stderr:   stderr,
	}
	if waitResp.Error != nil && waitResp.Error.Message != "" {
		return res, fmt.Errorf("helper container error: %s", waitResp.Error.Message)
	}
	if logErr != nil {
		return res, logErr
	}
	return res, nil
}

func (c *Client) containerLogs(ctx context.Context, id string) (string, string, error) {
	reqURL := "http://docker" + c.prefix(ctx) + "/containers/" + url.PathEscape(id) + "/logs?stdout=1&stderr=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch helper logs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", APIError{StatusCode: resp.StatusCode}
	}
	var stdout, stderr bytes.Buffer
	err = Demux(io.LimitReader(resp.Body, 2<<20), &stdout, &stderr)
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}
