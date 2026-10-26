package docker

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestDumpCompletionTail(t *testing.T) {
	run := "bakabel_0123456789abcdef0123456789abcdef"
	payload := "PGDMP" + strings.Repeat("payload", 100)
	marker := "\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00"
	for _, tc := range []struct {
		name, wire string
		ok         bool
	}{
		{"complete", payload + marker, true},
		{"missing", payload, false},
		{"partial_marker", payload + marker[:len(marker)-1], false},
		{"wrong_run", payload + "\x00BAKABEL_EXPORT_COMPLETE_V1:another_run_0123456789abcdef\x00", false},
		{"trailing_bytes", payload + marker + "x", false},
		{"no_archive", marker, false},
	} {
		for _, chunk := range []int{1, 7, len(tc.wire)} {
			t.Run(tc.name+"_chunk_"+string(rune('a'+chunk%26)), func(t *testing.T) {
				var out bytes.Buffer
				stream := newDumpStream(&out, run)
				for offset := 0; offset < len(tc.wire); {
					end := min(len(tc.wire), offset+chunk)
					n, err := stream.Write([]byte(tc.wire[offset:end]))
					if err != nil || n != end-offset {
						t.Fatal("stream write failed", n, err)
					}
					offset = end
				}
				if got := stream.Finish() == nil; got != tc.ok {
					t.Fatalf("completion accepted=%v want=%v", got, tc.ok)
				}
				if tc.ok && out.String() != payload {
					t.Fatal("completion marker leaked or payload changed")
				}
				if cap(stream.tail) > len(marker) {
					t.Fatal("tail grew beyond fixed completion marker")
				}
			})
		}
	}
}

func TestDumpCompletionBoundedAndSinkFailure(t *testing.T) {
	run := "bakabel_0123456789abcdef0123456789abcdef"
	stream := newDumpStream(io.Discard, run)
	payload := []byte(strings.Repeat("x", 1<<20))
	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatal(n, err)
	}
	if cap(stream.tail) > 128 {
		t.Fatal("large write retained payload")
	}
	bad := newDumpStream(failWriter{}, run)
	if _, err := bad.Write(payload); err == nil {
		t.Fatal("sink failure suppressed")
	}
}
