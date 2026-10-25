package docker

import (
	"context"
	"errors"
	"os"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/files"
)

// PreflightFileRestoreVolume never creates volumes. It inventories ALL container
// consumers, including stopped ones. Only an exact owned temporary worker may
// be explicitly allowed. Native daemon paths must be visible for physical alias
// checks; an inaccessible bind/volume source is unsupported, never assumed safe.
// Recheck immediately before restore, under the parent's installation lock;
// Docker has no atomic reserve-volume/no-other-consumers API. Privileged
// concurrent Docker administration must be excluded operationally.
func (c *Client) PreflightFileRestoreVolume(ctx context.Context, s backup.Snapshot, name string, allowed *Worker, forbidden ...string) (LocalVolume, error) {
	var zero LocalVolume
	m, e := s.Restorable()
	if e != nil || m.Kind != "volume" || len(m.Mounts) != 1 {
		return zero, errors.New("complete single-volume snapshot required")
	}
	d, e := c.Info(ctx)
	if e != nil {
		return zero, e
	}
	v, e := c.InspectLocalVolume(ctx, name)
	if e != nil {
		return zero, e
	}
	src := m.Mounts[0]
	if src.DaemonID == d.ID && src.Name == v.Name {
		return zero, errors.New("source volume cannot be restore target")
	}
	exclusions, e := c.fileConsumerExclusions(ctx, allowed, name, v.Mountpoint, forbidden)
	if e != nil {
		return zero, e
	}
	target, e := files.OpenRestore(s, v.Mountpoint, exclusions)
	if e != nil {
		return zero, e
	}
	if e = target.Close(); e != nil {
		return zero, e
	}
	return v, nil
}

// PreflightFileRestoreDirectory additionally excludes all Docker consumer
// storage, including stopped application bind mounts. It returns the opened,
// pinned target: keep it alive and call Restore rather than reopening its name.
// This is deliberately unsupported if native daemon paths are not inspectable.
func (c *Client) PreflightFileRestoreDirectory(ctx context.Context, s backup.Snapshot, destination string, allowed *Worker, forbidden ...string) (*files.RestoreTarget, error) {
	if _, e := s.Restorable(); e != nil {
		return nil, e
	}
	exclusions, e := c.fileConsumerExclusions(ctx, allowed, "", destination, forbidden)
	if e != nil {
		return nil, e
	}
	return files.OpenRestore(s, destination, exclusions)
}
func (c *Client) fileConsumerExclusions(ctx context.Context, allowed *Worker, name, destination string, forbidden []string) ([]string, error) {
	d, e := c.Info(ctx)
	if e != nil {
		return nil, e
	}
	if allowed != nil {
		if allowed.ContainerID == "" || allowed.DaemonID != d.ID {
			return nil, ErrQuarantine
		}
		if _, e = c.inspectWorker(ctx, *allowed); e != nil {
			return nil, e
		}
	}
	var consumers []struct {
		ID string `json:"Id"`
	}
	if e = c.request(ctx, "GET", "/containers/json?all=true", nil, &consumers); e != nil {
		return nil, e
	}
	exclusions := append([]string{}, forbidden...)
	for _, entry := range consumers {
		container, e := c.InspectContainer(ctx, entry.ID)
		if e != nil || container.ID != entry.ID {
			return nil, ErrQuarantine
		}
		if allowed != nil && container.ID == allowed.ContainerID {
			continue
		}
		for _, mount := range container.Mounts {
			if mount.Type != "volume" && mount.Type != "bind" {
				continue
			}
			if name != "" && mount.Name == name || fileOverlap(mount.Source, destination) {
				return nil, errors.New("restore target has a container consumer")
			}
			if !filePath(mount.Source) {
				return nil, errors.New("unverifiable consumer mount source")
			}
			st, err := os.Stat(mount.Source)
			if err != nil {
				return nil, errors.New("native consumer source identity unavailable")
			}
			if st.IsDir() {
				exclusions = append(exclusions, mount.Source)
			}
		}
	}
	return exclusions, nil
}
