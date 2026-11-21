package docker

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	LabelType             = "bakabel.type"
	LabelPaths            = "bakabel.paths"
	LabelPostgresDatabase = "bakabel.postgres.database"
	LabelPostgresUser     = "bakabel.postgres.user"
)

// Target describes one resolved backup target discovered from Docker labels.
type Target struct {
	ID                 string `json:"id"`
	Type               string `json:"type"` // "postgres" or "volume"
	Platform           string `json:"platform"`
	Stack              string `json:"stack"`
	Service            string `json:"service"`
	ContainerID        string `json:"container_id"`
	ContainerStartedAt string `json:"-"`

	// Postgres fields
	Database   string `json:"database,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	DBPassword string `json:"-"` // never serialized

	// Volume / SQLite fields
	VolumeName string `json:"volume,omitempty"`
	MountPath  string `json:"mount_path,omitempty"`
	DBPath     string `json:"db_path,omitempty"`
}

// DiscoverOptions controls Docker label discovery.
type DiscoverOptions struct {
	Platform string   // "auto", "swarm", or "compose"
	Scope    []string // optional stack/project allowlist
}

// DiscoverResult holds resolved platform metadata and discovered targets.
type DiscoverResult struct {
	Platform string   `json:"platform"`
	NodeID   string   `json:"node_id,omitempty"`
	Targets  []Target `json:"targets"`
}

// Discover inspects Docker labels and resolves all eligible backup targets.
func Discover(ctx context.Context, c *Client, opts DiscoverOptions) (DiscoverResult, error) {
	info, err := c.Info(ctx)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("inspect docker daemon: %w", err)
	}

	platform := opts.Platform
	if platform == "" || platform == "auto" {
		if info.Swarm.LocalNodeState == "active" && info.Swarm.ControlAvailable {
			platform = "swarm"
		} else {
			platform = "compose"
		}
	}

	self, _ := c.SelfContainer(ctx)
	protectedVolumes := make(map[string]struct{})
	selfID := ""
	if self != nil {
		selfID = self.ID
		for _, m := range self.Mounts {
			if m.Type == "volume" && m.Name != "" {
				protectedVolumes[m.Name] = struct{}{}
			}
		}
	}

	scopeSet := make(map[string]struct{}, len(opts.Scope))
	for _, s := range opts.Scope {
		scopeSet[s] = struct{}{}
	}

	res := DiscoverResult{Platform: platform, NodeID: info.Swarm.NodeID}
	switch platform {
	case "swarm":
		if info.Swarm.LocalNodeState != "active" || !info.Swarm.ControlAvailable {
			return res, errors.New("swarm mode requested, but connected Docker daemon is not an active Swarm manager")
		}
		targets, err := discoverSwarm(ctx, c, info.Swarm.NodeID, selfID, scopeSet, protectedVolumes)
		if err != nil {
			return res, err
		}
		res.Targets = targets
	case "compose":
		targets, err := discoverCompose(ctx, c, selfID, scopeSet, protectedVolumes)
		if err != nil {
			return res, err
		}
		res.Targets = targets
	default:
		return res, fmt.Errorf("unsupported platform %q", platform)
	}

	sort.Slice(res.Targets, func(i, j int) bool {
		return res.Targets[i].ID < res.Targets[j].ID
	})
	return res, nil
}

func discoverSwarm(
	ctx context.Context,
	c *Client,
	localNodeID, selfID string,
	scopeSet, protectedVolumes map[string]struct{},
) ([]Target, error) {
	services, err := c.ListServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list swarm services: %w", err)
	}

	var targets []Target
	for _, svc := range services {
		btype := strings.TrimSpace(svc.Spec.Labels[LabelType])
		if btype == "" {
			continue
		}
		stack := svc.Spec.Labels["com.docker.stack.namespace"]
		if len(scopeSet) > 0 {
			if _, ok := scopeSet[stack]; !ok {
				continue
			}
		}
		serviceName := svc.Spec.Name
		if stack != "" && strings.HasPrefix(serviceName, stack+"_") {
			serviceName = strings.TrimPrefix(serviceName, stack+"_")
		}

		tasks, err := c.ListRunningTasks(ctx, svc.ID)
		if err != nil {
			return nil, fmt.Errorf("list tasks for service %s: %w", svc.Spec.Name, err)
		}
		if len(tasks) == 0 {
			return nil, fmt.Errorf("service %s has no running task", svc.Spec.Name)
		}
		if len(tasks) > 1 {
			return nil, fmt.Errorf("service %s has %d running replicas; Bakabel requires exactly 1 running replica", svc.Spec.Name, len(tasks))
		}
		task := tasks[0]
		if task.NodeID != localNodeID {
			return nil, fmt.Errorf("unsupported placement: service %s runs on node %s, but Bakabel is on node %s", svc.Spec.Name, task.NodeID, localNodeID)
		}
		if task.Status.ContainerStatus.ContainerID == selfID {
			return nil, fmt.Errorf("refusing to back up Bakabel's own container (%s)", svc.Spec.Name)
		}

		ctr, err := c.InspectContainer(ctx, task.Status.ContainerStatus.ContainerID)
		if err != nil {
			return nil, fmt.Errorf("inspect container for service %s: %w", svc.Spec.Name, err)
		}
		resolved, err := resolveTarget(ctx, c, "swarm", stack, serviceName, svc.Spec.Labels, ctr, protectedVolumes)
		if err != nil {
			return nil, err
		}
		targets = append(targets, resolved...)
	}
	return targets, nil
}

func discoverCompose(
	ctx context.Context,
	c *Client,
	selfID string,
	scopeSet, protectedVolumes map[string]struct{},
) ([]Target, error) {
	containers, err := c.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	type svcKey struct{ stack, service string }
	seen := make(map[svcKey]int)
	var targets []Target

	for _, summary := range containers {
		btype := strings.TrimSpace(summary.Labels[LabelType])
		if btype == "" {
			continue
		}
		if summary.ID == selfID {
			return nil, errors.New("refusing to back up Bakabel's own container")
		}
		stack := summary.Labels["com.docker.compose.project"]
		if len(scopeSet) > 0 {
			if _, ok := scopeSet[stack]; !ok {
				continue
			}
		}
		service := summary.Labels["com.docker.compose.service"]
		if service == "" && len(summary.Names) > 0 {
			service = strings.TrimPrefix(summary.Names[0], "/")
		}
		if stack == "" {
			stack = "standalone"
		}
		key := svcKey{stack: stack, service: service}
		seen[key]++
		if seen[key] > 1 {
			return nil, fmt.Errorf("service %s/%s has multiple running containers; Bakabel requires exactly 1", stack, service)
		}

		ctr, err := c.InspectContainer(ctx, summary.ID)
		if err != nil {
			return nil, fmt.Errorf("inspect container %s: %w", summary.ID[:min(12, len(summary.ID))], err)
		}
		resolved, err := resolveTarget(ctx, c, "compose", stack, service, summary.Labels, ctr, protectedVolumes)
		if err != nil {
			return nil, err
		}
		targets = append(targets, resolved...)
	}
	return targets, nil
}

func resolveTarget(
	ctx context.Context,
	c *Client,
	platform, stack, service string,
	labels map[string]string,
	ctr Container,
	protectedVolumes map[string]struct{},
) ([]Target, error) {
	if stack == "" {
		stack = "default"
	}
	btype := strings.ToLower(strings.TrimSpace(labels[LabelType]))
	switch btype {
	case "postgres":
		env := parseEnv(ctr.Config.Env)
		user := strings.TrimSpace(labels[LabelPostgresUser])
		if user == "" {
			user = strings.TrimSpace(env["POSTGRES_USER"])
		}
		if user == "" {
			user = "postgres"
		}
		db := strings.TrimSpace(labels[LabelPostgresDatabase])
		if db == "" {
			db = strings.TrimSpace(env["POSTGRES_DB"])
		}
		if db == "" {
			db = user
		}
		return []Target{{
			ID:                 fmt.Sprintf("%s/%s/postgres/%s", stack, service, db),
			Type:               "postgres",
			Platform:           platform,
			Stack:              stack,
			Service:            service,
			ContainerID:        ctr.ID,
			ContainerStartedAt: ctr.State.StartedAt,
			Database:           db,
			DBUser:             user,
			DBPassword:         env["POSTGRES_PASSWORD"],
		}}, nil

	case "volume":
		rawPaths := strings.TrimSpace(labels[LabelPaths])
		if rawPaths == "" {
			return nil, fmt.Errorf("service %s/%s has bakabel.type=volume but is missing %s", stack, service, LabelPaths)
		}
		mountsByDest := make(map[string]Mount, len(ctr.Mounts))
		for _, m := range ctr.Mounts {
			mountsByDest[path.Clean(m.Destination)] = m
		}
		var out []Target
		seenPath := make(map[string]struct{})
		for _, part := range strings.Split(rawPaths, ",") {
			dest := strings.TrimSpace(part)
			if dest == "" {
				continue
			}
			if !strings.HasPrefix(dest, "/") {
				return nil, fmt.Errorf("service %s/%s: bakabel.paths entry %q must be an absolute path", stack, service, dest)
			}
			cleanDest := path.Clean(dest)
			if _, dup := seenPath[cleanDest]; dup {
				continue
			}
			seenPath[cleanDest] = struct{}{}

			m, ok := mountsByDest[cleanDest]
			if !ok {
				return nil, fmt.Errorf("service %s/%s: mount path %q not found on container", stack, service, cleanDest)
			}
			if m.Type != "volume" || m.Name == "" {
				return nil, fmt.Errorf("service %s/%s: mount %q is type %q; only named Docker volumes are supported", stack, service, cleanDest, m.Type)
			}
			if _, protected := protectedVolumes[m.Name]; protected {
				return nil, fmt.Errorf("service %s/%s: refusing to back up Bakabel's own volume %q", stack, service, m.Name)
			}
			vol, err := c.InspectVolume(ctx, m.Name)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: inspect volume %q: %w", stack, service, m.Name, err)
			}
			if vol.Driver != "local" || len(vol.Options) > 0 {
				return nil, fmt.Errorf("service %s/%s: volume %q uses unsupported driver/options (driver=%q)", stack, service, m.Name, vol.Driver)
			}
			out = append(out, Target{
				ID:                 fmt.Sprintf("%s/%s/volume/%s", stack, service, m.Name),
				Type:               "volume",
				Platform:           platform,
				Stack:              stack,
				Service:            service,
				ContainerID:        ctr.ID,
				ContainerStartedAt: ctr.State.StartedAt,
				VolumeName:         m.Name,
				MountPath:          cleanDest,
			})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("service %s/%s: %s resolved to no paths", stack, service, LabelPaths)
		}
		return out, nil

	case "sqlite":
		rawPaths := strings.TrimSpace(labels[LabelPaths])
		if rawPaths == "" {
			return nil, fmt.Errorf("service %s/%s has bakabel.type=sqlite but is missing %s", stack, service, LabelPaths)
		}
		var out []Target
		seenPath := make(map[string]struct{})
		for _, part := range strings.Split(rawPaths, ",") {
			rawFile := strings.TrimSpace(part)
			if rawFile == "" {
				continue
			}
			if !strings.HasPrefix(rawFile, "/") {
				return nil, fmt.Errorf("service %s/%s: bakabel.paths entry %q must be an absolute path", stack, service, rawFile)
			}
			cleanFile := path.Clean(rawFile)
			if _, dup := seenPath[cleanFile]; dup {
				continue
			}
			seenPath[cleanFile] = struct{}{}

			var matched *Mount
			matchedDest := ""
			for i := range ctr.Mounts {
				m := &ctr.Mounts[i]
				mDest := path.Clean(m.Destination)
				if cleanFile == mDest {
					return nil, fmt.Errorf("service %s/%s: bakabel.paths entry %q points to mount directory, expected a SQLite file path", stack, service, cleanFile)
				}
				prefix := mDest + "/"
				if mDest == "/" {
					prefix = "/"
				}
				if strings.HasPrefix(cleanFile, prefix) && len(mDest) > len(matchedDest) {
					matched = m
					matchedDest = mDest
				}
			}
			if matched == nil {
				return nil, fmt.Errorf("service %s/%s: sqlite path %q is not inside any container mount", stack, service, cleanFile)
			}
			if matched.Type != "volume" || matched.Name == "" {
				return nil, fmt.Errorf("service %s/%s: sqlite path %q is on mount type %q; only named Docker volumes are supported", stack, service, cleanFile, matched.Type)
			}
			if _, protected := protectedVolumes[matched.Name]; protected {
				return nil, fmt.Errorf("service %s/%s: refusing to back up Bakabel's own volume %q", stack, service, matched.Name)
			}
			vol, err := c.InspectVolume(ctx, matched.Name)
			if err != nil {
				return nil, fmt.Errorf("service %s/%s: inspect volume %q: %w", stack, service, matched.Name, err)
			}
			if vol.Driver != "local" || len(vol.Options) > 0 {
				return nil, fmt.Errorf("service %s/%s: volume %q uses unsupported driver/options (driver=%q)", stack, service, matched.Name, vol.Driver)
			}
			relPath := strings.TrimPrefix(cleanFile, matchedDest+"/")
			if matchedDest == "/" {
				relPath = strings.TrimPrefix(cleanFile, "/")
			}
			relPath = path.Clean(relPath)
			if relPath == "" || relPath == "." || strings.HasPrefix(relPath, "../") || relPath == ".." {
				return nil, fmt.Errorf("service %s/%s: invalid relative sqlite path %q", stack, service, cleanFile)
			}
			out = append(out, Target{
				ID:                 fmt.Sprintf("%s/%s/sqlite/%s", stack, service, strings.TrimPrefix(cleanFile, "/")),
				Type:               "sqlite",
				Platform:           platform,
				Stack:              stack,
				Service:            service,
				ContainerID:        ctr.ID,
				ContainerStartedAt: ctr.State.StartedAt,
				VolumeName:         matched.Name,
				MountPath:          matchedDest,
				DBPath:             relPath,
			})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("service %s/%s: %s resolved to no paths", stack, service, LabelPaths)
		}
		return out, nil

	default:
		return nil, fmt.Errorf("service %s/%s: unsupported %s=%q (expected postgres, sqlite, or volume)", stack, service, LabelType, btype)
	}
}

func parseEnv(items []string) map[string]string {
	m := make(map[string]string, len(items))
	for _, kv := range items {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}
