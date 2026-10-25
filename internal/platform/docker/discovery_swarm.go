package docker

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

type discoveryService struct {
	ID   string
	Spec struct {
		Name   string
		Labels map[string]string
		Mode   struct {
			Replicated    *struct{ Replicas *uint64 }
			Global        *struct{}
			ReplicatedJob *struct{}
			GlobalJob     *struct{}
		}
	}
}
type discoveryTask struct {
	ID, ServiceID, NodeID, DesiredState string
	Status                              struct {
		State           string
		ContainerStatus struct{ ContainerID string }
	}
}

func (c *Client) discoverSwarm(ctx context.Context, o DiscoveryOptions) ([]Target, error) {
	daemon, e := c.Info(ctx)
	if e != nil || !daemon.Swarm.ControlAvailable || daemon.Swarm.NodeID == "" {
		return nil, ErrUnsupportedSource
	}
	var list []discoveryService
	if e = c.request(ctx, "GET", "/services", nil, &list); e != nil {
		return nil, ErrDiscovery
	}
	targets := []Target{}
	seen := map[string]bool{}
	for _, summary := range list {
		project := summary.Spec.Labels["com.docker.stack.namespace"]
		if !inScope(o.Scope, project) {
			continue
		}
		if !validID(summary.ID) || seen[summary.ID] {
			return nil, ErrDiscovery
		}
		seen[summary.ID] = true
		var service discoveryService
		if e = c.request(ctx, "GET", "/services/"+summary.ID, nil, &service); e != nil || service.ID != summary.ID || service.Spec.Labels["com.docker.stack.namespace"] != project {
			return nil, ErrDiscovery
		}
		marked, e := sourceLabels(service.Spec.Labels)
		if e != nil {
			return nil, e
		}
		if !marked {
			continue
		}
		spec := service.Spec
		name, ok := strings.CutPrefix(spec.Name, project+"_")
		if !ok || !discoveryID.MatchString(name) {
			return nil, ErrDiscovery
		}
		if spec.Mode.Replicated == nil || spec.Mode.Replicated.Replicas == nil || *spec.Mode.Replicated.Replicas != 1 || spec.Mode.Global != nil || spec.Mode.ReplicatedJob != nil || spec.Mode.GlobalJob != nil {
			return nil, ErrUnsupportedSource
		}
		filters, _ := json.Marshal(map[string][]string{"service": {service.ID}})
		var tasks []discoveryTask
		if e = c.request(ctx, "GET", "/tasks?filters="+url.QueryEscape(string(filters)), nil, &tasks); e != nil {
			return nil, ErrDiscovery
		}
		var active []discoveryTask
		for _, task := range tasks {
			if task.ServiceID != service.ID {
				return nil, ErrDiscovery
			}
			if task.DesiredState == "shutdown" && terminalTask(task.Status.State) {
				continue
			}
			active = append(active, task)
		}
		if len(active) != 1 {
			return nil, ErrUnsupportedSource
		}
		task := active[0]
		if task.DesiredState != "running" || task.Status.State != "running" || task.NodeID != daemon.Swarm.NodeID || !validID(task.ID) || !validID(task.Status.ContainerStatus.ContainerID) {
			return nil, ErrUnsupportedSource
		}
		v, e := c.InspectContainer(ctx, task.Status.ContainerStatus.ContainerID)
		if e != nil || v.ID != task.Status.ContainerStatus.ContainerID || !v.State.Running || v.Config.Labels["com.docker.swarm.service.id"] != service.ID || v.Config.Labels["com.docker.swarm.task.id"] != task.ID || v.Config.Labels["com.docker.swarm.node.id"] != task.NodeID {
			return nil, ErrDiscovery
		}
		selected, e := c.discoveryTargets(ctx, o, project, name, spec.Labels, v)
		if e != nil {
			return nil, e
		}
		for _, t := range selected {
			if t.Source.DaemonID != daemon.ID {
				return nil, ErrDiscovery
			}
		}
		targets = append(targets, selected...)
	}
	current, e := c.Info(ctx)
	if e != nil || current.ID != daemon.ID || current.Swarm.NodeID != daemon.Swarm.NodeID || !current.Swarm.ControlAvailable {
		return nil, ErrDiscovery
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	for i := 1; i < len(targets); i++ {
		if targets[i].ID == targets[i-1].ID {
			return nil, ErrDiscovery
		}
	}
	return targets, nil
}
func terminalTask(state string) bool {
	switch state {
	case "complete", "shutdown", "failed", "rejected", "remove", "orphaned":
		return true
	}
	return false
}
