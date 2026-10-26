package docker

import (
	"bytes"
	"io"
)

const dumpCompletionPrefix = "\x00BAKABEL_EXPORT_COMPLETE_V1:"

// dumpStream retains only a fixed-size completion suffix. The archive itself is
// forwarded with backpressure, without staging or treating a transport EOF as
// evidence that the producer's final stdout bytes were delivered.
type dumpStream struct {
	out                  io.Writer
	tail, marker, header []byte
	err                  error
}

func newDumpStream(out io.Writer, run string) *dumpStream {
	marker := []byte(dumpCompletionPrefix + run + "\x00")
	return &dumpStream{out: out, marker: marker, tail: make([]byte, 0, len(marker)), header: make([]byte, 0, 5)}
}

func (s *dumpStream) forward(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	n, err := s.out.Write(p)
	if err != nil || n != len(p) {
		return ErrDumpFailed
	}
	if len(s.header) < 5 {
		s.header = append(s.header, p[:min(len(p), 5-len(s.header))]...)
	}
	return nil
}

func (s *dumpStream) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	excess := len(s.tail) + len(p) - len(s.marker)
	if excess <= 0 {
		s.tail = append(s.tail, p...)
		return len(p), nil
	}
	if excess <= len(s.tail) {
		s.err = s.forward(s.tail[:excess])
		if s.err != nil {
			return 0, s.err
		}
		copy(s.tail, s.tail[excess:])
		s.tail = append(s.tail[:len(s.tail)-excess], p...)
	} else {
		s.err = s.forward(s.tail)
		if s.err == nil {
			s.err = s.forward(p[:excess-len(s.tail)])
		}
		if s.err != nil {
			return 0, s.err
		}
		s.tail = append(s.tail[:0], p[len(p)-len(s.marker):]...)
	}
	return len(p), nil
}

func (s *dumpStream) Finish() error {
	if s.err != nil || !bytes.Equal(s.tail, s.marker) || !bytes.Equal(s.header, []byte("PGDMP")) {
		return ErrDumpFailed
	}
	return nil
}
