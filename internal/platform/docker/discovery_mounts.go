package docker

import (
	"context"
	"net/url"
	"path"
	"sort"
	"strings"
)

func cleanAbsolute(s string) bool {
	return strings.HasPrefix(s, "/") && path.Clean(s) == s && !strings.ContainsAny(s, "\x00\r\n")
}
func within(a, b string) bool   { return a == b || b == "/" || strings.HasPrefix(a, b+"/") }
func overlaps(a, b string) bool { return within(a, b) || within(b, a) }
func dangerousPath(s string) bool {
	if !cleanAbsolute(s) || s == "/" {
		return true
	}
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock", "/run/secrets", "/run/configs", "/proc", "/sys", "/dev"} {
		if overlaps(s, p) {
			return true
		}
	}
	return false
}

func (c *Client) discoveryTargets(ctx context.Context, o DiscoveryOptions, p, s string, labels map[string]string, v Container) ([]Target, error) {
	if labels["bakabel.type"] == "postgres" {
		t, e := c.discoveryTarget(ctx, o, p, s, labels, v)
		if e != nil {
			return nil, e
		}
		return []Target{t}, nil
	}
	source, e := c.CaptureSource(ctx, v.ID)
	if e != nil || source.ContainerID != v.ID || source.StartedAt != v.State.StartedAt {
		return nil, ErrDiscovery
	}
	if e := c.inspectDiscoveryMountConfig(ctx, v.ID); e != nil {
		return nil, e
	}
	protected, e := c.discoveryProtectedPaths(ctx, o)
	if e != nil {
		return nil, e
	}
	selected := strings.Split(labels["bakabel.paths"], ",")
	targets := []Target{}
	seen := map[string]bool{}
	for _, root := range selected {
		if dangerousPath(root) || seen[root] {
			return nil, ErrDiscovery
		}
		seen[root] = true
		for _, p := range protected {
			if overlaps(root, p) {
				return nil, ErrUnsupportedSource
			}
		}
		var mount Mount
		matches := 0
		for _, m := range v.Mounts {
			if m.Destination == root {
				mount = m
				matches++
				continue
			}
			// Never silently broaden a root or cross nested secret/bind mounts.
			if cleanAbsolute(m.Destination) && overlaps(root, m.Destination) {
				return nil, ErrUnsupportedSource
			}
		}
		if matches != 1 || mount.Type != "volume" || dangerousPath(mount.Source) {
			return nil, ErrUnsupportedSource
		}
		backing, e := c.InspectLocalVolume(ctx, mount.Name)
		if e != nil || backing.Mountpoint != mount.Source || !strings.HasSuffix(backing.Mountpoint, "/volumes/"+mount.Name+"/_data") {
			return nil, ErrUnsupportedSource
		}
		for _, p := range protected {
			if overlaps(mount.Source, p) {
				return nil, ErrUnsupportedSource
			}
		}
		targets = append(targets, Target{ID: o.Installation + "/" + o.Platform + "/" + p + "/" + s + "/volume/" + url.PathEscape(root), Kind: "volume", Project: p, Service: s, Source: source, Mounts: []Mount{mount}})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets, nil
}

// inspectDiscoveryMountConfig rejects volume-subpath mounts: Docker's volume
// identity is the whole backing root, and a subpath must never broaden to it.
// VolumeOptions.Subpath is defined by the Engine mount API, not source labels.
func (c *Client) inspectDiscoveryMountConfig(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrUnsupportedSource
	}
	var v struct {
		ID         string `json:"Id"`
		HostConfig *struct {
			Mounts []struct {
				Type          string
				VolumeOptions *struct{ Subpath string }
			}
		}
	}
	if e := c.request(ctx, "GET", "/containers/"+id+"/json", nil, &v); e != nil || v.ID != id || v.HostConfig == nil {
		return ErrUnsupportedSource
	}
	for _, m := range v.HostConfig.Mounts {
		if m.VolumeOptions != nil && m.VolumeOptions.Subpath != "" {
			return ErrUnsupportedSource
		}
	}
	return nil
}

func (c *Client) discoveryProtectedPaths(ctx context.Context, o DiscoveryOptions) ([]string, error) {
	socket, state := o.DockerSocket, o.StateDir
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	if state == "" {
		state = "/var/lib/bakabel"
	}
	protected := []string{socket, state}
	for _, p := range []string{o.PasswordFile, o.S3CredentialsFile} {
		if p != "" {
			protected = append(protected, p)
		}
	}
	if strings.HasPrefix(o.Repository, "/") {
		protected = append(protected, o.Repository)
	}
	for _, p := range protected {
		if !cleanAbsolute(p) || p == "/" {
			return nil, ErrDiscovery
		}
	}
	for _, p := range o.ProtectedNodePaths {
		if !cleanAbsolute(p) || p == "/" {
			return nil, ErrDiscovery
		}
		protected = append(protected, p)
	}
	if o.RunnerContainerID == "" {
		return protected, nil
	}
	runner, e := c.InspectContainer(ctx, o.RunnerContainerID)
	if e != nil || runner.ID != o.RunnerContainerID || !runner.State.Running {
		return nil, ErrDiscovery
	}
	// Exclude whole backing mounts, not merely a relative credential filename.
	for _, m := range runner.Mounts {
		if m.Type == "tmpfs" {
			continue
		}
		if !cleanAbsolute(m.Source) || !cleanAbsolute(m.Destination) {
			return nil, ErrUnsupportedSource
		}
		if m.Type == "volume" {
			v, e := c.InspectLocalVolume(ctx, m.Name)
			if e != nil || v.Mountpoint != m.Source {
				return nil, ErrUnsupportedSource
			}
		} else if m.Type != "bind" {
			return nil, ErrUnsupportedSource
		}
		protected = append(protected, m.Source)
	}
	return protected, nil
}
