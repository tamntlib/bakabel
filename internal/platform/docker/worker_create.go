package docker

import (
	"context"
	"net/url"
	"strings"

	"github.com/tamntlib/bakabel/internal/config"
)

// WorkerMount names explicit node-native bind files; Docker-created workers do
// not inherit scheduler or Swarm secret mounts. Mount paths are operator-trusted.
type WorkerMount struct {
	Source, Target string
	ReadOnly       bool
}
type WorkerSpec struct {
	Image     string
	Mounts    []WorkerMount
	Mode      string
	Resources config.WorkerResources
	// Fixed workflow-only permissions; never accept arbitrary environment/caps.
	S3, Files bool
	S3Region  string
}

// CreateWorker requires prior durable owner intent. Response loss is ambiguous;
// recover by the same never-reused random name, daemon and ownership labels.
func (c *Client) CreateWorker(ctx context.Context, w Worker, s WorkerSpec) (Worker, error) {
	if !w.valid() || w.ContainerID != "" || s.Image == "" || s.Resources.Validate() != nil {
		return w, ErrQuarantine
	}
	command := "_worker"
	if s.Mode == "workflow" {
		command = "_workflow"
	} else if s.Mode != "" {
		return w, ErrQuarantine
	}
	daemon, e := c.Info(ctx)
	if e != nil || daemon.ID != w.DaemonID {
		return w, ErrQuarantine
	}
	mounts := make([]map[string]any, 0, len(s.Mounts))
	for _, m := range s.Mounts {
		if len(m.Source) == 0 || m.Source[0] != '/' || len(m.Target) == 0 || m.Target[0] != '/' {
			return w, ErrQuarantine
		}
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": m.Source, "Target": m.Target, "ReadOnly": m.ReadOnly})
	}
	limits := s.Resources.Effective()
	config := map[string]any{
		"Image": s.Image, "Entrypoint": []string{"/usr/local/bin/bakabel"}, "Cmd": []string{command}, "Env": []string{},
		"Labels":     map[string]string{"bakabel.worker": "1", "bakabel.run": w.RunID, "bakabel.daemon": w.DaemonID},
		"HostConfig": map[string]any{"Mounts": mounts, "AutoRemove": false, "RestartPolicy": map[string]string{"Name": "no"}, "ReadonlyRootfs": true, "NetworkMode": "none", "NanoCpus": limits.CPUs * 1_000_000_000, "Memory": limits.MemoryMiB * (1 << 20), "CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges"}, "Tmpfs": map[string]string{"/tmp": "rw,nosuid,nodev,size=67108864"}, "LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "1m", "max-file": "1"}}},
	}
	if s.Mode != "workflow" && (s.S3 || s.Files || s.S3Region != "") {
		return w, ErrQuarantine
	}
	if strings.ContainsAny(s.S3Region, "\x00\r\n") {
		return w, ErrQuarantine
	}
	if s.Mode == "workflow" {
		config["Env"] = []string{"RESTIC_PASSWORD_FILE=/run/secrets/restic-password"}
		host := config["HostConfig"].(map[string]any)
		if s.S3 {
			host["NetworkMode"] = "bridge"
			config["Env"] = []string{"RESTIC_PASSWORD_FILE=/run/secrets/restic-password", "AWS_SHARED_CREDENTIALS_FILE=/run/secrets/aws", "AWS_DEFAULT_REGION=" + s.S3Region}
		}
		if s.Files {
			host["CapAdd"] = []string{"DAC_READ_SEARCH", "CHOWN", "FOWNER", "DAC_OVERRIDE", "FSETID"}
		}
	}
	var response struct {
		ID string `json:"Id"`
	}
	if e = c.request(ctx, "POST", "/containers/create?name="+url.QueryEscape(w.Name), config, &response); e != nil {
		return w, e
	}
	if !validID(response.ID) {
		return w, ErrQuarantine
	}
	w.ContainerID = response.ID
	if _, e = c.InspectWorker(ctx, w); e != nil {
		return w, e
	}
	return w, nil
}

// StartWorker must be invoked once, only AFTER exact ID and start authorization
// are durable. Never retry a failed start: recover/terminate instead.
func (c *Client) StartWorker(ctx context.Context, w Worker) error {
	v, e := c.inspectWorker(ctx, w)
	if e != nil || w.ContainerID == "" || v.State.Status != "created" || *v.State.Running {
		return ErrQuarantine
	}
	return c.request(ctx, "POST", "/containers/"+w.ContainerID+"/start", nil, nil)
}
