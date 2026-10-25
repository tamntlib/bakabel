package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestDiscoveryRejectsVolumeSubpathAndMissingMountConfig(t *testing.T) {
	for _, mode := range []string{"subpath", "missing host config"} {
		t.Run(mode, func(t *testing.T) {
			v := volumeContainer()
			v.Config.Labels["bakabel.paths"] = "/data"
			c := server(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.55/info":
					json.NewEncoder(w).Encode(map[string]string{"ID": "daemon"})
				case "/v1.55/containers/json":
					json.NewEncoder(w).Encode([]map[string]any{{"Id": v.ID, "Labels": v.Config.Labels}})
				case "/v1.55/containers/source/json":
					if mode == "missing host config" {
						json.NewEncoder(w).Encode(v)
						return
					}
					response := struct {
						Container
						HostConfig any
					}{Container: v, HostConfig: map[string]any{"Mounts": []map[string]any{{"Type": "volume", "Source": "data", "Target": "/data", "VolumeOptions": map[string]any{"Subpath": "subset"}}}}}
					json.NewEncoder(w).Encode(response)
				default:
					if !volumeAPI(w, r) {
						t.Errorf("unexpected request %s", r.URL.Path)
						w.WriteHeader(404)
					}
				}
			})
			got, e := c.Discover(context.Background(), discoveryOptions())
			if e == nil || got != nil {
				t.Fatal("unverifiable mount configuration accepted")
			}
		})
	}
}
