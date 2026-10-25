package docker

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAPIErrorNeverIncludesDaemonBody(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("password=SECRET source credentials"))
	})
	_, e := c.Info(context.Background())
	if e == nil || e.Error() != "docker API status 403" || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(e)
	}
}
func TestBoundedControlBufferRejectsOverflow(t *testing.T) {
	b := boundedBuffer{limit: 4}
	if n, e := b.Write([]byte("1234")); e != nil || n != 4 {
		t.Fatal(n, e)
	}
	if _, e := b.Write([]byte("secret")); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
	if b.String() != "1234" {
		t.Fatal(b.String())
	}
}
func TestPrimitiveValidationNoRequests(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid operation reached Engine: %s", r.URL.Path)
	})
	ctx := context.Background()
	for _, id := range []string{"", "source/name", "source?query=1", "source\nname", strings.Repeat("x", 129)} {
		if _, e := c.InspectContainer(ctx, id); e == nil {
			t.Fatal("invalid container accepted")
		}
		if _, e := c.PollExec(ctx, id); e == nil {
			t.Fatal("invalid exec accepted")
		}
		if e := c.StartExec(ctx, id, io.Discard, io.Discard); e == nil {
			t.Fatal("invalid start accepted")
		}
	}
	for _, cfg := range []ExecConfig{{}, {Cmd: []string{"fixed"}, Tty: true}, {Cmd: []string{"fixed"}, AttachStdin: true}} {
		if _, e := c.CreateExec(ctx, "source", cfg); e == nil {
			t.Fatal("invalid exec configuration accepted")
		}
	}
	for _, run := range []string{"", strings.Repeat("a", 64), "bakabel_quote'00000000", "bakabel_newline\n000000"} {
		if validToken(run) {
			t.Fatalf("unsafe run token %q", run)
		}
	}
	if e := Demux(strings.NewReader(""), nil, io.Discard); e == nil {
		t.Fatal("nil sink accepted")
	}
}
