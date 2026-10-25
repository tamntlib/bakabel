package restore

import (
	"testing"

	"github.com/tamntlib/bakabel/internal/backup"
	"github.com/tamntlib/bakabel/internal/platform/docker"
)

func TestDatabasePolicyMatchesNormalizesOrderButPreservesGrantMeaning(t *testing.T) {
	want := backup.PostgresMetadata{Owner: "owner", ACL: []backup.Grant{{Grantor: "owner", Grantee: "", Privilege: "CONNECT"}, {Grantor: "owner", Grantee: "reader", Privilege: "CONNECT", Grantable: true}}}
	got := docker.PostgresMetadata{Owner: "owner", ACL: []docker.Grant{{Grantor: "owner", Grantee: "reader", Privilege: "CONNECT", Grantable: true}, {Grantor: "owner", Grantee: "", Privilege: "CONNECT"}}}
	if !DatabasePolicyMatches(want, got) {
		t.Fatal("equivalent role-name grants rejected because of order")
	}
	for _, change := range []string{"grantor", "grant-option", "public", "owner"} {
		t.Run(change, func(t *testing.T) {
			altered := got
			altered.ACL = append([]docker.Grant{}, got.ACL...)
			switch change {
			case "grantor":
				altered.ACL[0].Grantor = "another"
			case "grant-option":
				altered.ACL[0].Grantable = false
			case "public":
				altered.ACL[1].Grantee = "PUBLIC"
			case "owner":
				altered.Owner = "another"
			}
			if DatabasePolicyMatches(want, altered) {
				t.Fatal("normalized comparison lost grant meaning")
			}
		})
	}
}
