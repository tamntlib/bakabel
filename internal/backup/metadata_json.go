package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// uniqueMetadataJSON rejects ambiguity before encoding/json's last-key-wins
// typed decode. Metadata has a small fixed schema; depth is bounded separately
// from its already-enforced byte limit. Key folding also covers Go's case-
// insensitive struct-field lookup; non-ASCII keys are not in the schema.
func uniqueMetadataJSON(raw []byte) error {
	invalid := errors.New("invalid or ambiguous snapshot metadata JSON")
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return invalid
		}
		token, err := decoder.Token()
		if err != nil {
			return invalid
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				key, ok := token.(string)
				if err != nil || !ok {
					return invalid
				}
				for _, c := range key {
					if c > 127 {
						return invalid
					}
				}
				key = strings.ToLower(key)
				if seen[key] {
					return invalid
				}
				seen[key] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
				return invalid
			}
		case json.Delim('['):
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
				return invalid
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid
	}
	return nil
}
