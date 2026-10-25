package backup

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestMetadataRejectsDuplicateKeysAtEveryLevel(t *testing.T) {
	m := Metadata{Version: 1, Kind: "postgres", Source: "fixture", Paths: []string{"/dump"}, Postgres: &PostgresMetadata{Database: "fixture", ClusterID: "123", DatabaseOID: "456", ServerVersion: 180006, ClientVersion: 180006, Format: "custom", Owner: "owner", ACL: []Grant{{Grantor: "owner", Grantee: "", Privilege: "CONNECT"}}}}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	base := string(encoded)
	for _, test := range []struct{ name, old, replacement string }{
		{"top-level", `"version":1`, `"version":999,"version":1`},
		{"same-value", `"version":1`, `"version":1,"version":1`},
		{"escaped-key", `"version":1`, `"\u0076ersion":999,"version":1`},
		{"case-folded", `"version":1`, `"VERSION":999,"version":1`},
		{"physical-identity", `"cluster_id":"123"`, `"cluster_id":"999","cluster_id":"123"`},
		{"nested-acl", `"grantor":"owner"`, `"grantor":"other","grantor":"owner"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := strings.Replace(base, test.old, test.replacement, 1)
			if raw == base {
				t.Fatal("regression mutation missed its field")
			}
			tags := []string{"bakabel.meta=" + base64.RawURLEncoding.EncodeToString([]byte(raw)), "bakabel.status=complete", "bakabel.run=fixture"}
			if _, _, _, err := DecodeTags(tags); err == nil {
				t.Fatal("ambiguous metadata keys accepted")
			}
		})
	}
}
