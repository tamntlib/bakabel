package docker

import (
	"encoding/json"
	"errors"
	"reflect"
)

// Trusted template0 inventory, postgres:18.6-alpine3.24, server 180006.
// Runtime database creation is deliberately NOT used to derive an empty baseline.
const restoreBaseline = `{"objects":[],"extensions":[{"name":"plpgsql","schema":"pg_catalog","version":"1.0"}],"namespaces":["public"],"global_objects":[{"kind":"language","name":"c"},{"kind":"language","name":"internal"},{"kind":"language","name":"plpgsql"},{"kind":"language","name":"sql"}],"namespace_policies":[{"acl":[{"grantee":"PUBLIC","grantor":"pg_database_owner","privilege":"USAGE","grant_option":false},{"grantee":"pg_database_owner","grantor":"pg_database_owner","privilege":"CREATE","grant_option":false},{"grantee":"pg_database_owner","grantor":"pg_database_owner","privilege":"USAGE","grant_option":false}],"name":"public","owner":"pg_database_owner"}]}`

// Namespace dependencies include operators, collations, domains, text search,
// schema default ACLs, etc. Explicit coverage also includes classes/procs/types,
// extensions and non-schema/global objects. See the independent PG18 baseline proof.
const restoreInventorySQL = `WITH ns AS (
 SELECT oid,nspname FROM pg_catalog.pg_namespace
 WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
), addresses AS (
 SELECT d.classid,d.objid,d.objsubid FROM pg_catalog.pg_depend d JOIN ns
 ON d.refclassid='pg_catalog.pg_namespace'::regclass AND d.refobjid=ns.oid
 UNION SELECT 'pg_catalog.pg_class'::regclass,c.oid,0 FROM pg_catalog.pg_class c JOIN ns ON c.relnamespace=ns.oid
 UNION SELECT 'pg_catalog.pg_proc'::regclass,p.oid,0 FROM pg_catalog.pg_proc p JOIN ns ON p.pronamespace=ns.oid
 UNION SELECT 'pg_catalog.pg_type'::regclass,t.oid,0 FROM pg_catalog.pg_type t JOIN ns ON t.typnamespace=ns.oid
), objects AS (
 SELECT DISTINCT a.classid::regclass::text AS catalog,i.type,i.schema,i.name,i.identity
 FROM addresses a CROSS JOIN LATERAL pg_catalog.pg_identify_object(a.classid,a.objid,a.objsubid) i
), extensions AS (
 SELECT e.extname AS name,e.extversion AS version,n.nspname AS schema
 FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace
), global_objects AS (
 SELECT 'event_trigger' AS kind,evtname::text AS name FROM pg_catalog.pg_event_trigger
 UNION ALL SELECT 'foreign_data_wrapper',fdwname FROM pg_catalog.pg_foreign_data_wrapper
 UNION ALL SELECT 'foreign_server',srvname FROM pg_catalog.pg_foreign_server
 UNION ALL SELECT 'publication',pubname FROM pg_catalog.pg_publication
 UNION ALL SELECT 'subscription',subname FROM pg_catalog.pg_subscription
 UNION ALL SELECT 'language',lanname FROM pg_catalog.pg_language
 UNION ALL SELECT 'large_object',oid::text FROM pg_catalog.pg_largeobject_metadata
 -- These catalogs have no namespace. FirstNormalObjectId is 16384 on stock
 -- PG18; bootstrap/system casts/access methods have lower OIDs. Without these
 -- gates a user cast between system types or table AM looks deceptively empty.
 UNION ALL SELECT 'cast',oid::text FROM pg_catalog.pg_cast WHERE oid>=16384
 UNION ALL SELECT 'access_method',amname FROM pg_catalog.pg_am WHERE oid>=16384
 UNION ALL SELECT 'transform',oid::text FROM pg_catalog.pg_transform WHERE oid>=16384
 UNION ALL SELECT 'global_default_acl',pg_get_userbyid(defaclrole)||':'||defaclobjtype::text FROM pg_catalog.pg_default_acl WHERE defaclnamespace=0
), namespace_policies AS (
 SELECT n.nspname AS name,pg_get_userbyid(n.nspowner) AS owner,
 (SELECT jsonb_agg(jsonb_build_object(
 'grantor',pg_get_userbyid(a.grantor),
 'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
 'privilege',a.privilege_type,'grant_option',a.is_grantable)
 ORDER BY pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable)
 FROM aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a) AS acl
 FROM pg_catalog.pg_namespace n JOIN ns ON ns.oid=n.oid
)
SELECT pg_catalog.jsonb_build_object(
 'namespaces',COALESCE((SELECT jsonb_agg(nspname ORDER BY nspname) FROM ns),'[]'::jsonb),
 'namespace_policies',COALESCE((SELECT jsonb_agg(to_jsonb(namespace_policies) ORDER BY name) FROM namespace_policies),'[]'::jsonb),
 'objects',COALESCE((SELECT jsonb_agg(to_jsonb(objects) ORDER BY catalog,type,schema,name,identity) FROM objects),'[]'::jsonb),
 'extensions',COALESCE((SELECT jsonb_agg(to_jsonb(extensions) ORDER BY name) FROM extensions),'[]'::jsonb),
 'global_objects',COALESCE((SELECT jsonb_agg(to_jsonb(global_objects) ORDER BY kind,name) FROM global_objects),'[]'::jsonb))`

func checkRestoreInventory(raw []byte) error {
	var got, want any
	if json.Unmarshal(raw, &got) != nil || json.Unmarshal([]byte(restoreBaseline), &want) != nil || !reflect.DeepEqual(got, want) {
		return errors.New("target differs from supported PG18 template0 catalog baseline")
	}
	return nil
}
