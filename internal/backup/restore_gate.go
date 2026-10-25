package backup

import (
	"errors"
	"reflect"
)

// Restorable is a repository-only validation; it needs no source or scheduler
// state. Destination identity/emptiness checks are a separate mandatory gate.
func (s Snapshot) Restorable() (Metadata, error) {
	m, status, _, err := DecodeTags(s.Tags)
	if err != nil {
		return Metadata{}, err
	}
	if !validSnapshotID(s.ID) || status != "complete" {
		return Metadata{}, errors.New("restore requires an exact complete snapshot")
	}
	if !reflect.DeepEqual(s.Paths, m.Paths) {
		return Metadata{}, errors.New("snapshot layout differs from recovery metadata")
	}
	return m, nil
}
