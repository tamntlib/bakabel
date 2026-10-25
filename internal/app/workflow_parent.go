package app

import (
	"errors"
	"github.com/tamntlib/bakabel/internal/backup"
	"reflect"
	"time"
)

// Restic 0.18.1 --stdin-from-command selects its parent BEFORE it sets the
// virtual stdin path: host,paths sees an empty path filter. Pin a verified same-
// source parent explicitly, or --force for the first dump. Never cross targets.
func postgresParentArgs(snaps []backup.Snapshot, source, host string) ([]string, error) {
	var id string
	var latest time.Time
	paths := []string{postgresPath(source)}
	for _, s := range snaps {
		if s.Hostname != host || !reflect.DeepEqual(s.Paths, paths) {
			continue
		}
		m, status, _, e := backup.DecodeTags(s.Tags)
		if e != nil || m.Source != source || m.Kind != "postgres" || !reflect.DeepEqual(m.Paths, paths) {
			return nil, errors.New("ambiguous postgres parent metadata")
		}
		if status != "complete" {
			continue
		}
		when, e := time.Parse(time.RFC3339Nano, s.Time)
		if e != nil {
			return nil, errors.New("invalid parent timestamp")
		}
		if len(s.ID) != 64 {
			return nil, errors.New("invalid parent identity")
		}
		if id == "" || when.After(latest) {
			latest = when
			id = s.ID
		}
	}
	if id == "" {
		return []string{"--force"}, nil
	}
	return []string{"--parent", id}, nil
}
