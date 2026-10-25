package app

import (
	"bufio"
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
func digestTap() (*io.PipeWriter, *streamDigest) {
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
		d.err = docker.Demux(br, d, io.Discard)
	}()
	return writer, d
}
