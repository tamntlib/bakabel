package docker

import (
	"context"
	"net/http"
	"testing"
)

func TestFileRestoreConsumerMountsInspectStoppedConsumers(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.55/containers/json":
			w.Write([]byte(`[{"Id":"stopped"}]`))
		case "/v1.55/containers/stopped/json":
			w.Write([]byte(`{"Id":"stopped","State":{"Running":false,"StartedAt":"2026-01-01T00:00:00Z"},"Mounts":[{"Type":"volume","Source":"/node/volume/_data","Name":"fixture","Destination":"/data"}]}`))
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(500)
		}
	})
	mounts, e := c.FileRestoreConsumerMounts(context.Background())
	if e != nil || len(mounts) != 1 || mounts[0].Source != "/node/volume/_data" {
		t.Fatal(mounts, e)
	}
}
