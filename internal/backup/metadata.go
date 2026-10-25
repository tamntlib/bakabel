// Package backup contains platform-independent backup records and repository rules.
package backup

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

const maxMetadata = 16 * 1024

// Metadata travels with its snapshot, not with the scheduler's local state.
type Metadata struct {
	Version  int               `json:"version"`
	Kind     string            `json:"kind"`
	Source   string            `json:"source"`
	Paths    []string          `json:"paths,omitempty"`
	Postgres *PostgresMetadata `json:"postgres,omitempty"`
	Mounts   []MountMetadata   `json:"mounts,omitempty"`
}

type MountMetadata struct {
	DaemonID     string `json:"daemon_id"`
	NodeID       string `json:"node_id"`
	Type         string `json:"type"`
	Name         string `json:"name,omitempty"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	SnapshotPath string `json:"snapshot_path"`
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	// FilesystemPath is resolved from the actual mounted source's mountinfo,
	// not from a label. It detects separately bind-mounted child aliases.
	FilesystemPath string `json:"filesystem_path,omitempty"`
}

// Grant uses role names, never role OIDs: OIDs differ on a new cluster. An
// empty Grantee denotes PostgreSQL PUBLIC, which has no role OID.
type Grant struct {
	Grantor   string `json:"grantor"`
	Grantee   string `json:"grantee"`
	Privilege string `json:"privilege"`
	Grantable bool   `json:"grantable"`
}

type PostgresMetadata struct {
	Database      string  `json:"database"`
	ClusterID     string  `json:"cluster_id"`
	DatabaseOID   string  `json:"database_oid"`
	ServerVersion int     `json:"server_version"`
	ClientVersion int     `json:"client_version"`
	Format        string  `json:"format"`
	Owner         string  `json:"owner"`
	ACL           []Grant `json:"acl"`
}

func (m Metadata) validate() error {
	if m.Version != 1 || m.Source == "" || strings.ContainsAny(m.Source, "\x00\r\n") {
		return errors.New("unsupported or missing snapshot metadata")
	}
	if m.Kind != "volume" && m.Kind != "postgres" {
		return errors.New("unsupported backup type")
	}
	if len(m.Paths) == 0 {
		return errors.New("missing snapshot paths")
	}
	for _, p := range m.Paths {
		if p == "/" || !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
			return errors.New("invalid snapshot path")
		}
	}
	if m.Kind == "postgres" {
		p := m.Postgres
		if p == nil || p.Database == "" || !digits(p.ClusterID) || !digits(p.DatabaseOID) || p.ServerVersion <= 0 || p.ClientVersion <= 0 || p.Format != "custom" || p.Owner == "" || p.ACL == nil {
			return errors.New("missing PostgreSQL identity or recovery handoff")
		}
		seen := map[Grant]bool{}
		for _, g := range p.ACL {
			if g.Grantor == "" || (g.Privilege != "CONNECT" && g.Privilege != "CREATE" && g.Privilege != "TEMPORARY") || seen[g] {
				return errors.New("invalid or duplicate PostgreSQL ACL")
			}
			seen[g] = true
		}
	} else if m.Postgres != nil {
		return errors.New("PostgreSQL handoff on non-database snapshot")
	}
	if m.Kind == "volume" {
		if len(m.Mounts) != len(m.Paths) {
			return errors.New("missing physical mount metadata")
		}
		for i, mount := range m.Mounts {
			if mount.FilesystemPath != "" && (!path.IsAbs(mount.FilesystemPath) || path.Clean(mount.FilesystemPath) != mount.FilesystemPath || strings.ContainsAny(mount.FilesystemPath, "\x00\r\n")) {
				return errors.New("invalid filesystem backing path")
			}
			if mount.DaemonID == "" || mount.NodeID == "" || (mount.Type != "bind" && mount.Type != "volume") || mount.Inode == 0 || mount.Source == "" || !path.IsAbs(mount.Source) || path.Clean(mount.Source) != mount.Source || !path.IsAbs(mount.Destination) || path.Clean(mount.Destination) != mount.Destination || mount.SnapshotPath != m.Paths[i] {
				return errors.New("invalid physical mount metadata")
			}
		}
	}
	return nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func EncodeTags(m Metadata, status, run string) ([]string, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if !validStatus(status) || !validRun(run) {
		return nil, errors.New("invalid snapshot status or run")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMetadata {
		return nil, errors.New("snapshot metadata too large")
	}
	return []string{"bakabel.meta=" + base64.RawURLEncoding.EncodeToString(raw), "bakabel.status=" + status, "bakabel.run=" + run}, nil
}

func DecodeTags(tags []string) (Metadata, string, string, error) {
	var m Metadata
	fields := map[string]string{}
	for _, tag := range tags {
		key, value, ok := strings.Cut(tag, "=")
		if !ok || !strings.HasPrefix(key, "bakabel.") {
			continue
		}
		if key != "bakabel.meta" && key != "bakabel.status" && key != "bakabel.run" {
			continue
		}
		if _, exists := fields[key]; exists {
			return m, "", "", errors.New("conflicting snapshot tags")
		}
		if len(value) > maxMetadata*2 {
			return m, "", "", errors.New("snapshot metadata too large")
		}
		fields[key] = value
	}
	if !validStatus(fields["bakabel.status"]) || !validRun(fields["bakabel.run"]) {
		return m, "", "", errors.New("missing snapshot status/run")
	}
	raw, err := base64.RawURLEncoding.DecodeString(fields["bakabel.meta"])
	if err != nil || len(raw) > maxMetadata {
		return m, "", "", errors.New("invalid snapshot metadata encoding")
	}
	if err := uniqueMetadataJSON(raw); err != nil {
		return m, "", "", err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, "", "", fmt.Errorf("invalid snapshot metadata: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return m, "", "", errors.New("trailing snapshot metadata")
	}
	if err := m.validate(); err != nil {
		return m, "", "", err
	}
	return m, fields["bakabel.status"], fields["bakabel.run"], nil
}

func validStatus(s string) bool { return s == "unknown" || s == "partial" || s == "complete" }

func validRun(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
