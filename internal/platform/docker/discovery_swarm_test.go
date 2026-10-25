package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func swarmContract(t *testing.T, mode string) *Client {
	t.Helper()
	service := map[string]any{"ID": "svc", "Spec": map[string]any{"Name": "app_db", "Labels": map[string]string{"com.docker.stack.namespace": "app", "bakabel.type": "postgres", "bakabel.postgres.database": "serviceDB"}, "Mode": map[string]any{"Replicated": map[string]any{"Replicas": 1}}}}
	spec := service["Spec"].(map[string]any)
	switch mode {
	case "zero replicas":
		spec["Mode"] = map[string]any{"Replicated": map[string]any{"Replicas": 0}}
	case "two replicas":
		spec["Mode"] = map[string]any{"Replicated": map[string]any{"Replicas": 2}}
	case "global":
		spec["Mode"] = map[string]any{"Global": map[string]any{}}
	case "missing replicas":
		spec["Mode"] = map[string]any{"Replicated": map[string]any{}}
	case "bad label":
		spec["Labels"].(map[string]string)["bakabel.worker_image"] = "SECRET"
	case "no override":
		delete(spec["Labels"].(map[string]string), "bakabel.postgres.database")
	case "files":
		labels := spec["Labels"].(map[string]string)
		delete(labels, "bakabel.postgres.database")
		labels["bakabel.type"] = "volume"
		labels["bakabel.paths"] = "/data"
	case "bad name":
		spec["Name"] = "some_other_name"
	}
	task := map[string]any{"ID": "task", "ServiceID": "svc", "NodeID": "node", "DesiredState": "running", "Status": map[string]any{"State": "running", "ContainerStatus": map[string]any{"ContainerID": "source"}}}
	switch mode {
	case "off node":
		task["NodeID"] = "remote"
	case "task stopped":
		task["Status"].(map[string]any)["State"] = "shutdown"
	case "wrong service":
		task["ServiceID"] = "other"
	case "missing container":
		task["Status"].(map[string]any)["ContainerStatus"] = map[string]any{}
	case "desired stopped":
		task["DesiredState"] = "shutdown"
	}
	source := discoveryContainer("source", "unused", "unused", "SECRET")
	source.Config.Labels["bakabel.postgres.database"] = "containerDB"
	source.Config.Labels["com.docker.swarm.service.id"] = "svc"
	source.Config.Labels["com.docker.swarm.task.id"] = "task"
	source.Config.Labels["com.docker.swarm.node.id"] = "node"
	if mode == "files" {
		source.Mounts = []Mount{volumeContainer().Mounts[0]}
		source.Config.Labels["bakabel.paths"] = "/SECRET"
	}
	switch mode {
	case "wrong container task":
		source.Config.Labels["com.docker.swarm.task.id"] = "other"
	case "wrong container node":
		source.Config.Labels["com.docker.swarm.node.id"] = "other"
	case "wrong container service":
		source.Config.Labels["com.docker.swarm.service.id"] = "other"
	case "container stopped":
		source.State.Running = false
	case "wrong inspect ID":
		source.ID = "replacement"
	}
	return server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("discovery performed write")
		}
		switch r.URL.Path {
		case "/v1.55/info":
			manager, node := true, "node"
			if mode == "not manager" {
				manager = false
			}
			if mode == "missing node" {
				node = ""
			}
			json.NewEncoder(w).Encode(map[string]any{"ID": "daemon", "Swarm": map[string]any{"NodeID": node, "ControlAvailable": manager}})
		case "/v1.55/services":
			json.NewEncoder(w).Encode([]any{service, map[string]any{"ID": "external", "Spec": map[string]any{"Labels": map[string]string{"com.docker.stack.namespace": "outside", "bakabel.type": "SECRET"}}}})
		case "/v1.55/services/svc":
			json.NewEncoder(w).Encode(service)
		case "/v1.55/tasks":
			var filters map[string][]string
			if e := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); e != nil || len(filters["service"]) != 1 || filters["service"][0] != "svc" {
				t.Error("missing exact service task filter")
			}
			tasks := []any{task}
			if mode == "zero tasks" {
				tasks = nil
			}
			if mode == "two tasks" {
				tasks = append(tasks, task)
			}
			if mode == "historical terminal" {
				tasks = append(tasks, map[string]any{"ID": "old", "ServiceID": "svc", "NodeID": "remote", "DesiredState": "shutdown", "Status": map[string]any{"State": "shutdown"}})
			}
			json.NewEncoder(w).Encode(tasks)
		case "/v1.55/containers/source/json":
			json.NewEncoder(w).Encode(struct {
				Container
				HostConfig struct{ Mounts []any }
			}{Container: source})
		default:
			if volumeAPI(w, r) {
				return
			}
			t.Errorf("unexpected swarm route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
}
func TestDiscoverySwarmServiceLabels(t *testing.T) {
	for _, mode := range []string{"valid", "historical terminal", "no override"} {
		t.Run(mode, func(t *testing.T) {
			c := swarmContract(t, mode)
			o := discoveryOptions()
			o.Platform = "swarm"
			got, e := c.Discover(context.Background(), o)
			if e != nil {
				t.Fatal(e)
			}
			db := "serviceDB"
			if mode == "no override" {
				db = "app"
			}
			if len(got) != 1 || got[0].Database != db || got[0].ID != "fixture/swarm/app/db/postgres/"+db || got[0].Source.ContainerID != "source" {
				t.Fatalf("wrong service metadata %#v", got)
			}
		})
	}
}
func TestDiscoverySwarmFilesUsesServiceMountPaths(t *testing.T) {
	c := swarmContract(t, "files")
	o := discoveryOptions()
	o.Platform = "swarm"
	got, e := c.Discover(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 1 || got[0].Kind != "volume" || len(got[0].Mounts) != 1 || got[0].Mounts[0].Destination != "/data" || got[0].ID != "fixture/swarm/app/db/volume/%2Fdata" {
		t.Fatalf("wrong service mount selection %#v", got)
	}
}

func TestDiscoverySwarmFailsUnavailable(t *testing.T) {
	for _, mode := range []string{"not manager", "missing node", "zero replicas", "two replicas", "global", "missing replicas", "zero tasks", "two tasks", "off node", "task stopped", "wrong service", "missing container", "desired stopped", "wrong container task", "wrong container node", "wrong container service", "container stopped", "wrong inspect ID", "bad label", "bad name"} {
		t.Run(mode, func(t *testing.T) {
			c := swarmContract(t, mode)
			o := discoveryOptions()
			o.Platform = "swarm"
			got, e := c.Discover(context.Background(), o)
			if e == nil || got != nil {
				t.Fatalf("unsupported Swarm source %#v", got)
			}
			if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("unsafe error")
			}
		})
	}
}
