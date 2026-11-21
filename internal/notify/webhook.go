// Package notify delivers optional failure webhooks without leaking secrets.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// FailurePayload is the sanitized JSON body sent to the configured webhook URL.
type FailurePayload struct {
	Installation string    `json:"installation"`
	Status       string    `json:"status"`
	Error        string    `json:"error"`
	FinishedAt   time.Time `json:"finished_at"`
}

// SendFailure posts a failure notification to webhookURL with a bounded timeout and no redirects.
func SendFailure(ctx context.Context, webhookURL string, payload FailurePayload) error {
	if webhookURL == "" {
		return nil
	}
	u, err := url.Parse(webhookURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("invalid webhook URL")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bakabel/2")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("webhook redirects are not allowed")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("webhook request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
