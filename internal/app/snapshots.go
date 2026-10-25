package app

import (
	"github.com/tamntlib/bakabel/internal/backup"
	"reflect"
)

type snapshotRow struct {
	SnapshotID string           `json:"snapshotID"`
	Source     string           `json:"source,omitempty"`
	Kind       string           `json:"type,omitempty"`
	Time       string           `json:"time"`
	Status     string           `json:"status"`
	Metadata   *backup.Metadata `json:"metadata,omitempty"`
}

func describeSnapshot(s backup.Snapshot) snapshotRow {
	row := snapshotRow{SnapshotID: s.ID, Time: s.Time, Status: "unknown"}
	m, status, _, e := backup.DecodeTags(s.Tags)
	if e == nil && reflect.DeepEqual(m.Paths, s.Paths) {
		row.Source = m.Source
		row.Kind = m.Kind
		row.Metadata = &m
		row.Status = status
	}
	return row
}
