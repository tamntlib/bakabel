package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func volumeContainer() Container {
	v := discoveryContainer("source", "app", "files", "volume")
	v.Config.Labels["bakabel.paths"] = "/other,/data"
	v.Mounts = []Mount{{Type: "volume", Name: "data", Source: "/var/lib/docker/volumes/data/_data", Destination: "/data", RW: true}, {Type: "volume", Name: "other", Source: "/var/lib/docker/volumes/other/_data", Destination: "/other", RW: true}}
	return v
}
func volumeAPI(w http.ResponseWriter, r *http.Request) bool {
	for _, name := range []string{"data", "other", "state", "repository"} {
		if r.URL.Path == "/v1.55/volumes/"+name {
			json.NewEncoder(w).Encode(map[string]any{"Name": name, "Driver": "local", "Scope": "local", "Options": map[string]string{}, "Mountpoint": "/var/lib/docker/volumes/" + name + "/_data"})
			return true
		}
	}
	return false
}
func TestDiscoveryOneTargetPerVolume(t *testing.T) {
	containers := []Container{volumeContainer()}
	c := discoveryFixture(t, &containers, volumeAPI)
	o := discoveryOptions()
	o.PasswordFile = "/credentials/restic"
	o.Repository = "/repository"
	got, e := c.Discover(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 2 || len(got[0].Mounts) != 1 || len(got[1].Mounts) != 1 || got[0].Mounts[0].Destination != "/data" || got[1].Mounts[0].Destination != "/other" || got[0].ID != "fixture/compose/app/files/volume/%2Fdata" || got[0].Database != "" {
		t.Fatalf("targets %#v", got)
	}
	containers[0].Config.Labels["bakabel.paths"] = "/data,/other"
	next, e := c.Discover(context.Background(), o)
	if e != nil || !reflect.DeepEqual(got, next) {
		t.Fatal("path ordering affected targets", e)
	}
}
func TestDiscoveryRejectsUnsafeMountSelection(t *testing.T) {
	for _, paths := range []string{"", "data", "/data/../other", "/data/", "/", "/var/run/docker.sock", "/run/secrets", "/data,/data", "/data, /other", "/data/subdir", "/state", "/repository", "/credentials", "/data,,/other", "/data\n"} {
		t.Run(paths, func(t *testing.T) {
			v := volumeContainer()
			v.Config.Labels["bakabel.paths"] = paths
			containers := []Container{v}
			c := discoveryFixture(t, &containers, volumeAPI)
			o := discoveryOptions()
			o.StateDir = "/state"
			o.Repository = "/repository"
			o.PasswordFile = "/credentials/restic"
			got, e := c.Discover(context.Background(), o)
			if e == nil || got != nil {
				t.Fatalf("unsafe paths accepted %#v", got)
			}
		})
	}
}
func TestDiscoveryRejectsUnprovenVolumeIdentity(t *testing.T) {
	for _, mode := range []string{"bind", "tmpfs", "missing name", "missing source", "wrong source", "nonlocal driver", "driver options", "missing scope", "uninspectable", "missing options", "nested mounts", "source root", "source socket", "source state", "repository alias", "credentials alias", "duplicate mount root"} {
		t.Run(mode, func(t *testing.T) {
			v := volumeContainer()
			v.Config.Labels["bakabel.paths"] = "/data"
			o := discoveryOptions()
			o.Repository = "/repository"
			o.PasswordFile = "/credentials/restic"
			switch mode {
			case "bind":
				v.Mounts[0].Type = "bind"
			case "tmpfs":
				v.Mounts[0].Type = "tmpfs"
			case "missing name":
				v.Mounts[0].Name = ""
			case "missing source":
				v.Mounts[0].Source = ""
			case "wrong source":
				v.Mounts[0].Source = "/elsewhere"
			case "nested mounts":
				v.Mounts = append(v.Mounts, Mount{Type: "bind", Source: "/secret", Destination: "/data/secret"})
			case "source root":
				v.Mounts[0].Source = "/"
			case "source socket":
				v.Mounts[0].Source = "/var/run/docker.sock"
			case "source state":
				o.StateDir = v.Mounts[0].Source
			case "repository alias":
				o.Repository = v.Mounts[0].Source + "/repo"
			case "credentials alias":
				o.PasswordFile = v.Mounts[0].Source + "/password"
			case "duplicate mount root":
				v.Mounts = append(v.Mounts, v.Mounts[0])
			}
			containers := []Container{v}
			c := discoveryFixture(t, &containers, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == "/v1.55/volumes/data" {
					if mode == "uninspectable" {
						w.WriteHeader(403)
						w.Write([]byte("SECRET"))
						return true
					}
					driver, scope := "local", "local"
					options := map[string]string{}
					if mode == "nonlocal driver" {
						driver = "nfs"
					}
					if mode == "driver options" {
						options = map[string]string{"type": "none", "o": "bind", "device": "SECRET"}
					}
					if mode == "missing scope" {
						scope = ""
					}
					response := map[string]any{"Name": "data", "Driver": driver, "Scope": scope, "Options": options, "Mountpoint": "/var/lib/docker/volumes/data/_data"}
					if mode == "missing options" {
						delete(response, "Options")
					}
					json.NewEncoder(w).Encode(response)
					return true
				}
				return volumeAPI(w, r)
			})
			got, e := c.Discover(context.Background(), o)
			if e == nil || got != nil {
				t.Fatalf("unsupported volume accepted %#v", got)
			}
			if strings.Contains(e.Error(), "SECRET") {
				t.Fatal("unsafe error")
			}
		})
	}
}
func TestDiscoveryRunnerMappedExclusions(t *testing.T) {
	for _, field := range []string{"repository", "state", "password", "s3"} {
		t.Run(field, func(t *testing.T) {
			source := volumeContainer()
			source.Config.Labels["bakabel.paths"] = "/data"
			runner := discoveryContainer("runner", "infrastructure", "bakabel", "")
			runner.Mounts = []Mount{{Type: "volume", Name: "data", Source: source.Mounts[0].Source, Destination: "/protected"}}
			containers := []Container{source, runner}
			c := discoveryFixture(t, &containers, volumeAPI)
			o := discoveryOptions()
			o.RunnerContainerID = "runner"
			o.Repository = "s3:https://fixture/bucket"
			o.StateDir = "/var/lib/bakabel"
			o.PasswordFile = "/credentials/restic"
			switch field {
			case "repository":
				o.Repository = "/protected/repository"
			case "state":
				o.StateDir = "/protected/state"
			case "password":
				o.PasswordFile = "/protected/password"
			case "s3":
				o.S3CredentialsFile = "/protected/s3"
			}
			got, e := c.Discover(context.Background(), o)
			if e == nil || got != nil {
				t.Fatal("runner backing storage exclusion missed")
			}
		})
	}
}
