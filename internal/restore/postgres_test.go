package restore

import (
	"context"
	"strings"
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func fixtureSnapshot(t *testing.T) backup.Snapshot {
	t.Helper()
	m := backup.Metadata{Version: 1, Kind: "postgres", Source: "lost-source", Paths: []string{"/database.dump"}, Postgres: &backup.PostgresMetadata{Database: "lost", ClusterID: "123", DatabaseOID: "456", ServerVersion: 180006, ClientVersion: 180006, Format: "custom", Owner: "owner", ACL: []backup.Grant{{Grantor: "owner", Grantee: "", Privilege: "CONNECT"}}}}
	tags, e := backup.EncodeTags(m, "complete", "restore_test")
	if e != nil {
		t.Fatal(e)
	}
	return backup.Snapshot{ID: strings.Repeat("a", 64), Paths: m.Paths, Tags: tags}
}

func TestPostgresRejectsUnrestorableBeforeTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*backup.Snapshot)
	}{
		{"short-id", func(s *backup.Snapshot) { s.ID = "latest" }},
		{"missing-metadata", func(s *backup.Snapshot) { s.Tags = nil }},
		{"partial", func(s *backup.Snapshot) {
			for i, tag := range s.Tags {
				if tag == "bakabel.status=complete" {
					s.Tags[i] = "bakabel.status=partial"
				}
			}
		}},
		{"unknown", func(s *backup.Snapshot) {
			for i, tag := range s.Tags {
				if tag == "bakabel.status=complete" {
					s.Tags[i] = "bakabel.status=unknown"
				}
			}
		}},
		{"layout", func(s *backup.Snapshot) { s.Paths = []string{"/other"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixtureSnapshot(t)
			tc.mutate(&s)
			r, e := RestorePostgres(context.Background(), backup.Repository{}, s, nil, docker.Source{}, "db", "postgres")
			if e == nil || r.Status == "restored" {
				t.Fatalf("unexpected success: %+v %v", r, e)
			}
		})
	}
}
