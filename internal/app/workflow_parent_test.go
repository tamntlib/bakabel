package app

import (
	"github.com/tamntlib/bakabel/internal/backup"
	"reflect"
	"strings"
	"testing"
)

func TestPostgresParentNeverUsesOtherSourceOrFileSnapshot(t *testing.T) {
	host := "installation"
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: "source-a", Paths: []string{postgresPath("source-a")}, Postgres: &backup.PostgresMetadata{Database: "db", ClusterID: "1", DatabaseOID: "2", ServerVersion: 180006, ClientVersion: 180006, Owner: "postgres", Format: "custom", ACL: []backup.Grant{}}}
	tags, e := backup.EncodeTags(m, "complete", "first")
	if e != nil {
		t.Fatal(e)
	}
	own := backup.Snapshot{ID: strings.Repeat("a", 64), Hostname: host, Paths: m.Paths, Tags: tags, Time: "2026-01-01T00:00:00Z"}
	other := own
	other.ID = strings.Repeat("b", 64)
	other.Paths = []string{postgresPath("other")}
	other.Time = "2026-01-02T00:00:00Z"
	got, e := postgresParentArgs([]backup.Snapshot{other}, m.Source, host)
	if e != nil || !reflect.DeepEqual(got, []string{"--force"}) {
		t.Fatal(got, e)
	}
	got, e = postgresParentArgs([]backup.Snapshot{own, other}, m.Source, host)
	if e != nil || !reflect.DeepEqual(got, []string{"--parent", own.ID}) {
		t.Fatal(got, e)
	}
}
