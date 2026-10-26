package app

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/tamntlib/bakabel/internal/platform/docker"
	"hash"
	"io"
	"net/http"
)

type streamDigest struct {
	n int64
	hash.Hash
	err  error
	done chan struct{}
}

func (d *streamDigest) Write(p []byte) (int, error) {
	n, e := d.Hash.Write(p)
	d.n += int64(n)
	return n, e
}

// Observes actual Engine stdout independently of the helper/Restic reader. Only
// a streaming digest is retained, never the dump or raw framed Docker response.
func digestTap(run string) (*io.PipeWriter, *streamDigest) {
	reader, writer := io.Pipe()
	d := &streamDigest{Hash: sha256.New(), done: make(chan struct{})}
	go func() {
		defer close(d.done)
		defer reader.Close()
		br := bufio.NewReader(reader)
		response, e := http.ReadResponse(br, nil)
		if e != nil {
			d.err = e
			return
		}
		if response.StatusCode != http.StatusSwitchingProtocols {
			d.err = fmt.Errorf("expected raw exec upgrade, got %d", response.StatusCode)
			return
		}
		// An independent test observer separates the producer's fixed protocol
		// suffix from archive bytes, then hashes every actual source archive byte.
		marker := []byte("\x00BAKABEL_EXPORT_COMPLETE_V1:" + run + "\x00")
		observer := &sourceArchiveDigest{sink: d, keep: len(marker)}
		d.err = docker.Demux(br, observer, io.Discard)
		if d.err == nil && !bytes.Equal(observer.tail.Bytes(), marker) {
			d.err = fmt.Errorf("source completion trailer missing")
		}
	}()
	return writer, d
}

type sourceArchiveDigest struct {
	sink io.Writer
	keep int
	tail bytes.Buffer
}

func (s *sourceArchiveDigest) Write(p []byte) (int, error) {
	s.tail.Write(p)
	if n := s.tail.Len() - s.keep; n > 0 {
		if _, err := s.sink.Write(s.tail.Next(n)); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
