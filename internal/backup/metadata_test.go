package backup

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMetadataRoundTripAndStatus(t *testing.T) {
	m := fileMetadata()
	tags, err := EncodeTags(m, "unknown", "fixture-run")
	if err != nil {
		t.Fatal(err)
	}
	got, status, run, err := DecodeTags(tags)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != m.Source || got.Kind != m.Kind || status != "unknown" || run != "fixture-run" || got.Paths[0] != "/data" {
		t.Fatalf("wrong metadata: %+v %s %s", got, status, run)
	}
	tags = append(tags, "bakabel.status=complete")
	if _, _, _, err := DecodeTags(tags); err == nil {
		t.Fatal("conflicting statuses accepted")
	}
}

func TestMetadataRejectsMissingVersionAndOversizedInput(t *testing.T) {
	for _, tags := range [][]string{nil, {"bakabel.meta=bad", "bakabel.status=complete", "bakabel.run=x"}, {"bakabel.meta=" + strings.Repeat("x", 40000)}} {
		if _, _, _, err := DecodeTags(tags); err == nil {
			t.Fatalf("invalid tags accepted: %v", len(tags))
		}
	}
	if _, err := EncodeTags(Metadata{Kind: "volume", Source: "x", Paths: []string{"/data"}}, "complete", "x"); err == nil {
		t.Fatal("unversioned metadata accepted")
	}
}

func TestMetadataRejectsAmbiguousJSONAndUnsafePaths(t *testing.T) {
	base := `{"version":1,"kind":"volume","source":"files","paths":["/data"]}`
	for _, raw := range []string{base + ` {}`, strings.Replace(base, `"/data"`, `"/data/../etc"`, 1), strings.Replace(base, `"/data"`, `"data"`, 1), strings.Replace(base, `"/data"`, `"/"`, 1), strings.Replace(base, `"volume"`, `"postgres"`, 1)} {
		tags := []string{"bakabel.meta=" + base64.RawURLEncoding.EncodeToString([]byte(raw)), "bakabel.status=complete", "bakabel.run=run"}
		if _, _, _, err := DecodeTags(tags); err == nil {
			t.Fatalf("invalid metadata accepted: %s", raw)
		}
	}
}

func TestPostgresMetadataHandoffAndPhysicalIdentity(t *testing.T) {
	m := Metadata{Version: 1, Kind: "postgres", Source: "compose/fixture/db", Paths: []string{"/database.dump"},
		Postgres: &PostgresMetadata{Database: "dbname=literal uri", ClusterID: "12345", DatabaseOID: "16384", ServerVersion: 180006, ClientVersion: 180006, Format: "custom", Owner: "owner", ACL: []Grant{{Grantor: "owner", Grantee: "owner", Privilege: "CONNECT"}}}}
	tags, err := EncodeTags(m, "complete", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, err := DecodeTags(tags)
	if err != nil || got.Postgres.Database != m.Postgres.Database || got.Postgres.ACL[0].Grantor != "owner" {
		t.Fatalf("handoff differs: %+v %v", got, err)
	}
	m.Postgres.ClusterID = ""
	if _, err = EncodeTags(m, "complete", "fixture"); err == nil {
		t.Fatal("missing physical identity accepted")
	}
	m.Postgres.ClusterID = "12345"
	m.Postgres.ACL = append(m.Postgres.ACL, m.Postgres.ACL[0])
	if _, err = EncodeTags(m, "complete", "fixture"); err == nil {
		t.Fatal("duplicate ACL accepted")
	}
}
