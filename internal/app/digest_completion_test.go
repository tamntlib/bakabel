package app

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"testing"
)

func TestSourceDigestSeparatesCompletionFromArchive(t *testing.T) {
	run := "0123456789abcdef0123456789abcdef"
	payload := []byte("PGDMParchive-payload")
	marker := []byte("\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00")
	for _, ok := range []bool{true, false} {
		t.Run(fmt.Sprint(ok), func(t *testing.T) {
			w, d := digestTap(run)
			raw := append([]byte(nil), payload...)
			if ok {
				raw = append(raw, marker...)
			}
			go func() {
				fmt.Fprint(w, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
				header := []byte{1, 0, 0, 0, 0, 0, 0, byte(len(raw))}
				w.Write(header)
				w.Write(raw)
				w.Close()
			}()
			<-d.done
			if !ok {
				if d.err == nil {
					t.Fatal("unproven source completion accepted")
				}
				return
			}
			sum := sha256.Sum256(payload)
			if d.err != nil || d.n != int64(len(payload)) || !bytes.Equal(d.Sum(nil), sum[:]) {
				t.Fatal("archive-only source digest mismatch", d.err, d.n)
			}

		})
	}
}
