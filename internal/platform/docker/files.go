package docker

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"github.com/tamntlib/bakabel/internal/files"
)

// LocalVolume is an Engine volume inspect response, not just its name. Drivers
// and local-driver options can hide aliases/network filesystems and are refused.
type LocalVolume struct {
	Name       string
	Driver     string
	Scope      string
	Mountpoint string
	Options    map[string]string
}

func (c *Client) InspectLocalVolume(ctx context.Context, name string) (LocalVolume, error) {
	var v LocalVolume
	if !validID(name) || name == "." || name == ".." {
		return v, errors.New("invalid volume name")
	}
	wire := struct {
		Name, Driver, Scope, Mountpoint string
		Options                         json.RawMessage
	}{}
	if e := c.request(ctx, "GET", "/volumes/"+name, nil, &wire); e != nil {
		return v, e
	}
	v.Name = wire.Name
	v.Driver = wire.Driver
	v.Scope = wire.Scope
	v.Mountpoint = wire.Mountpoint
	if len(wire.Options) == 0 || json.Unmarshal(wire.Options, &v.Options) != nil {
		return v, errors.New("missing or invalid volume options")
	}
	if v.Name != name || v.Driver != "local" || v.Scope != "local" || len(v.Options) != 0 || !filePath(v.Mountpoint) {
		return v, errors.New("only inspectable option-free local volumes supported")
	}
	return v, nil
}

// PrepareFileVolume resolves precisely one complete mount, never a subdirectory
// or a bind path from a label. Capture must subsequently stat the actual mount.
// Reinvoke before creating the worker to detect source incarnation/mount drift.
func (c *Client) PrepareFileVolume(ctx context.Context, s Source, destination string) (files.Volume, error) {
	var result files.Volume
	if !filePath(destination) {
		return result, errors.New("exact clean mount required")
	}
	state, e := c.CheckSource(ctx, s)
	if e != nil || state != SourceRunning {
		return result, ErrQuarantine
	}
	d, e := c.Info(ctx)
	if e != nil {
		return result, e
	}
	v, e := c.InspectContainer(ctx, s.ContainerID)
	if e != nil {
		return result, e
	}
	if v.ID != s.ContainerID || v.State.StartedAt != s.StartedAt || !v.State.Running || d.ID != s.DaemonID {
		return result, ErrQuarantine
	}
	if v.Config.Labels["bakabel.type"] == "postgres" || fileOverlap(destination, "/var/lib/postgresql") {
		return result, errors.New("raw PostgreSQL data is not a file target")
	}
	for _, env := range v.Config.Env {
		if pg, ok := strings.CutPrefix(env, "PGDATA="); ok {
			if !filePath(pg) || fileOverlap(destination, pg) {
				return result, errors.New("raw PGDATA is not a file target")
			}
		}
	}
	var selected []Mount
	for _, m := range v.Mounts {
		if m.Destination == destination {
			selected = append(selected, m)
		} else if strings.HasPrefix(m.Destination, destination+"/") {
			return result, errors.New("nested mounts cannot be represented by a single-volume snapshot")
		}
	}
	if len(selected) != 1 || selected[0].Type != "volume" {
		return result, errors.New("exact local volume mount required")
	}
	m := selected[0]
	vol, e := c.InspectLocalVolume(ctx, m.Name)
	if e != nil {
		return result, e
	}
	if m.Source != vol.Mountpoint {
		return result, errors.New("container volume backing differs from inspect")
	}
	node := d.Swarm.NodeID
	if node == "" {
		node = d.ID
	}
	return files.Volume{DaemonID: d.ID, NodeID: node, Name: vol.Name, Mountpoint: vol.Mountpoint, Destination: destination}, nil
}
func fileOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
func filePath(p string) bool {
	return p != "/" && path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}
