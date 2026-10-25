package state

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

const MaxRecordBytes = 4096
const MaxResultBytes = 512

// Every on-disk value is a flat, identifiers-only object; reject ambiguity,
// unsupported keys/case, duplicates, nulls and trailing values without echoing data.
func decodeRecord(r io.Reader, limit int, dst any, fields string) error {
	b, e := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if e != nil {
		return e
	}
	if len(b) > limit {
		return ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return ErrCorrupt
	}
	seen := make(map[string]bool)
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return ErrCorrupt
		}
		key, ok := t.(string)
		if !ok || seen[key] || !strings.Contains(","+fields+",", ","+key+",") {
			return ErrCorrupt
		}
		seen[key] = true
		var v any
		if e = d.Decode(&v); e != nil {
			return ErrCorrupt
		}
		if key == "workerStartAuthorized" {
			if _, ok := v.(bool); !ok {
				return ErrCorrupt
			}
		} else if _, ok := v.(string); !ok {
			return ErrCorrupt
		}
	}
	if t, e = d.Token(); e != nil || t != json.Delim('}') {
		return ErrCorrupt
	}
	if _, e = d.Token(); e != io.EOF {
		return ErrCorrupt
	}
	if e = json.Unmarshal(b, dst); e != nil {
		return ErrCorrupt
	}
	return nil
}
