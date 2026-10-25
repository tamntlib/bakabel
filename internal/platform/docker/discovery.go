package docker

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var ErrDiscovery = errors.New("source discovery failed")
var ErrUnsupportedSource = errors.New("unsupported source storage or placement")

type DiscoveryOptions struct {
	Installation, Platform string
	Scope                  []string
	// Paths are daemon-native when RunnerContainerID is empty. Otherwise they
	// are resolved from this explicitly identified runner's inspected mounts.
	RunnerContainerID                                                   string
	DockerSocket, StateDir, Repository, PasswordFile, S3CredentialsFile string
	// ProtectedNodePaths comes from the scheduler's inspected mounts (including
	// credential/config mounts), resolved by the trusted runtime mount planner.
	ProtectedNodePaths []string
}

// DiscoverOptions is an alias for callers using the shorter operation name.
type DiscoverOptions = DiscoveryOptions

type Target struct {
	ID, Kind, Project, Service string
	Source                     Source
	// Database is frozen from platform labels or container POSTGRES_DB. Always
	// pass it to PreparePostgresDatabase; container labels must not override it.
	Database, DatabaseOverride string
	Mounts                     []Mount
}

// Discover performs read-only discovery. It never creates containers or volumes.
// A marked but unsupported/unavailable service fails the whole fixed plan.
func (c *Client) Discover(ctx context.Context, o DiscoveryOptions) ([]Target, error) {
	if !discoveryID.MatchString(o.Installation) || o.Platform != "compose" && o.Platform != "swarm" || len(o.Scope) == 0 {
		return nil, ErrDiscovery
	}
	seen := map[string]bool{}
	for _, s := range o.Scope {
		if !discoveryID.MatchString(s) || seen[s] {
			return nil, ErrDiscovery
		}
		seen[s] = true
	}
	initial, e := c.Info(ctx)
	if e != nil {
		return nil, ErrDiscovery
	}
	var targets []Target
	if o.Platform == "swarm" {
		targets, e = c.discoverSwarm(ctx, o)
	} else {
		targets, e = c.discoverCompose(ctx, o)
	}
	if e != nil {
		return nil, e
	}
	current, e := c.Info(ctx)
	if e != nil || current.ID != initial.ID {
		return nil, ErrDiscovery
	}
	for _, target := range targets {
		if target.Source.DaemonID != initial.ID {
			return nil, ErrDiscovery
		}
	}
	return targets, nil
}

var discoveryID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func inScope(scope []string, project string) bool {
	for _, s := range scope {
		if s == project {
			return true
		}
	}
	return false
}

func sourceLabels(labels map[string]string) (bool, error) {
	marked := false
	for k := range labels {
		if !strings.HasPrefix(k, "bakabel.") {
			continue
		}
		marked = true
		if k != "bakabel.type" && k != "bakabel.paths" && k != "bakabel.postgres.database" {
			return false, ErrDiscovery
		}
	}
	if !marked {
		return false, nil
	}
	switch labels["bakabel.type"] {
	case "postgres":
		if _, ok := labels["bakabel.paths"]; ok {
			return false, ErrDiscovery
		}
	case "volume":
		if _, ok := labels["bakabel.postgres.database"]; ok {
			return false, ErrDiscovery
		}
	default:
		return false, ErrDiscovery
	}
	return true, nil
}

func (c *Client) discoverCompose(ctx context.Context, o DiscoveryOptions) ([]Target, error) {
	var list []struct {
		ID     string `json:"Id"`
		Labels map[string]string
	}
	if e := c.request(ctx, "GET", "/containers/json?all=1", nil, &list); e != nil {
		return nil, ErrDiscovery
	}
	groups := map[string][]Container{}
	for _, entry := range list {
		p, s := entry.Labels["com.docker.compose.project"], entry.Labels["com.docker.compose.service"]
		if !inScope(o.Scope, p) {
			continue
		}
		v, e := c.InspectContainer(ctx, entry.ID)
		if e != nil || v.ID != entry.ID || v.Config.Labels["com.docker.compose.project"] != p || v.Config.Labels["com.docker.compose.service"] != s {
			return nil, ErrDiscovery
		}
		groups[p+"/"+s] = append(groups[p+"/"+s], v)
	}
	targets := []Target{}
	for _, group := range groups {
		marked := false
		for _, v := range group {
			m, e := sourceLabels(v.Config.Labels)
			if e != nil {
				return nil, e
			}
			marked = marked || m
		}
		if !marked {
			continue
		}
		if len(group) != 1 {
			return nil, ErrUnsupportedSource
		}
		v := group[0]
		p, s := v.Config.Labels["com.docker.compose.project"], v.Config.Labels["com.docker.compose.service"]
		if !discoveryID.MatchString(s) || !v.State.Running {
			return nil, ErrDiscovery
		}
		selected, e := c.discoveryTargets(ctx, o, p, s, v.Config.Labels, v)
		if e != nil {
			return nil, e
		}
		targets = append(targets, selected...)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets, nil
}

func (c *Client) discoveryTarget(ctx context.Context, o DiscoveryOptions, p, s string, labels map[string]string, v Container) (Target, error) {
	t := Target{Kind: labels["bakabel.type"], Project: p, Service: s, DatabaseOverride: labels["bakabel.postgres.database"]}
	if t.Kind != "postgres" {
		return Target{}, ErrUnsupportedSource
	}
	t.Database = t.DatabaseOverride
	if t.Database == "" {
		found := false
		for _, entry := range v.Config.Env {
			if value, ok := strings.CutPrefix(entry, "POSTGRES_DB="); ok {
				if found {
					return Target{}, ErrDiscovery
				}
				found = true
				t.Database = value
			}
		}
	}
	if t.Database == "" || len(t.Database) > 256 || !utf8.ValidString(t.Database) || strings.ContainsAny(t.Database, "\x00\r\n") {
		return Target{}, ErrDiscovery
	}
	source, e := c.CaptureSource(ctx, v.ID)
	if e != nil || source.ContainerID != v.ID || source.StartedAt != v.State.StartedAt {
		return Target{}, ErrDiscovery
	}
	t.Source = source
	t.ID = o.Installation + "/" + o.Platform + "/" + p + "/" + s + "/" + t.Kind + "/" + url.PathEscape(t.Database)
	return t, nil
}
