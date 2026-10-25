package app

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/tamntlib/bakabel/internal/files"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

// RuntimePaths are scheduler-visible paths, not arbitrary node-native bind
// sources. Every worker source is resolved from this scheduler's Engine inspect.
type RuntimePaths struct {
	Installation, StateDir, Repository, PasswordFile, Socket, CredentialsFile string
}

type RuntimeMountPlan struct {
	NodeState          string
	Mounts             []docker.WorkerMount
	ProtectedNodePaths []string
	Protected          []files.ProtectedIdentity
	Repository         string
}

func inside(root, p string) bool { return root == p || strings.HasPrefix(p, root+"/") }
func overlap(a, b string) bool   { return inside(a, b) || inside(b, a) }

func inspectedPath(mounts []docker.Mount, p string, write bool) (string, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsAny(p, "\x00\r\n") {
		return "", errors.New("invalid runtime path")
	}
	selected := -1
	for i, m := range mounts {
		if m.Destination == "/" || !inside(m.Destination, p) {
			continue
		}
		if selected != -1 && m.Destination == mounts[selected].Destination {
			return "", errors.New("ambiguous runtime mount")
		}
		if selected == -1 || len(m.Destination) > len(mounts[selected].Destination) {
			selected = i
		}
	}
	if selected == -1 {
		return "", errors.New("runtime path is not an inspected scheduler mount")
	}
	m := mounts[selected]
	if (m.Type != "bind" && m.Type != "volume") || m.Source == "/" || !filepath.IsAbs(m.Source) || filepath.Clean(m.Source) != m.Source || (write && !m.RW) {
		return "", errors.New("unsupported runtime mount")
	}
	rel, err := filepath.Rel(m.Destination, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("invalid runtime mapping")
	}
	return filepath.Join(m.Source, rel), nil
}

// PlanRuntimeMounts does not read secret contents or manufacture Swarm secret
// inheritance. Native secret mounts absent from Engine Mounts are unsupported;
// use explicit inspected read-only credential file/volume mounts instead.
func PlanRuntimeMounts(self docker.Container, p RuntimePaths) (RuntimeMountPlan, error) {
	var plan RuntimeMountPlan
	if p.Installation == "" || self.Config.Labels["bakabel.installation"] != p.Installation || self.Config.Labels["bakabel.role"] != "scheduler" {
		return plan, errors.New("scheduler identity does not match installation")
	}
	add := func(path, target string, write bool) (string, error) {
		node, err := inspectedPath(self.Mounts, path, write)
		if err != nil {
			return "", err
		}
		plan.Mounts = append(plan.Mounts, docker.WorkerMount{Source: node, Target: target, ReadOnly: !write})
		return node, nil
	}
	var err error
	plan.NodeState, err = add(p.StateDir, p.StateDir, true)
	if err != nil {
		return RuntimeMountPlan{}, err
	}
	plan.Repository = p.Repository
	nodeRepo := ""
	if !strings.HasPrefix(p.Repository, "s3:") {
		nodeRepo, err = add(p.Repository, "/repository", true)
		if err != nil {
			return RuntimeMountPlan{}, err
		}
		if overlap(plan.NodeState, nodeRepo) {
			return RuntimeMountPlan{}, errors.New("repository and state overlap")
		}
		plan.Repository = "/repository"
	}
	password, err := add(p.PasswordFile, workerPassword, false)
	if err != nil {
		return RuntimeMountPlan{}, err
	}
	if overlap(plan.NodeState, password) || (nodeRepo != "" && overlap(nodeRepo, password)) {
		return RuntimeMountPlan{}, errors.New("credentials overlap state or repository")
	}
	if _, err = add(p.Socket, workerSocket, false); err != nil {
		return RuntimeMountPlan{}, err
	}
	if p.CredentialsFile != "" {
		credentials, err := add(p.CredentialsFile, "/run/secrets/aws", false)
		if err != nil {
			return RuntimeMountPlan{}, err
		}
		if overlap(plan.NodeState, credentials) || (nodeRepo != "" && overlap(nodeRepo, credentials)) {
			return RuntimeMountPlan{}, errors.New("credentials overlap state or repository")
		}
	}
	for _, m := range self.Mounts {
		if filepath.IsAbs(m.Source) {
			plan.ProtectedNodePaths = append(plan.ProtectedNodePaths, m.Source)
		}
	}
	return plan, nil
}
