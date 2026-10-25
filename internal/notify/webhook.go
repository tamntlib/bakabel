// Package notify reports operational failure independently of backup outcome.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

type Event struct {
	Installation string `json:"installation"`
	RunID        string `json:"run_id,omitempty"`
	Status       string `json:"status"`
}

// Failure sends one bounded request. The endpoint is a credential-file reference;
// raw URLs, transport errors and response bodies never become diagnostics.
func Failure(ctx context.Context, urlFile string, event Event) error {
	if urlFile == "" {
		return nil
	}
	failed := errors.New("failure notification could not be delivered")
	if event.Installation == "" || len(event.Installation) > 128 || len(event.RunID) > 128 || strings.ContainsAny(event.Installation+event.RunID, "\x00\r\n") || (event.Status != "failed" && event.Status != "blocked" && event.Status != "overdue") {
		return failed
	}
	fd, err := syscall.Open(urlFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return failed
	}
	file := os.NewFile(uintptr(fd), "webhook endpoint")
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 8192 {
		return failed
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return failed
	}
	endpoint, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return failed
	}
	body, err := json.Marshal(event)
	if err != nil {
		return failed
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return failed
	}
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return failed
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return failed
	}
	return nil
}
