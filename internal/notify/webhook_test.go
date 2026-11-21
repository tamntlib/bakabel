package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendFailureAndRedirectRejection(t *testing.T) {
	var got FailurePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	payload := FailurePayload{
		Installation: "bakabel",
		Status:       "failed",
		Error:        "target failed",
		FinishedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := SendFailure(context.Background(), srv.URL+"/ok", payload); err != nil {
		t.Fatalf("SendFailure failed: %v", err)
	}
	if got.Installation != "bakabel" || got.Error != "target failed" {
		t.Fatalf("unexpected received payload: %+v", got)
	}
	if err := SendFailure(context.Background(), srv.URL+"/redirect", payload); err == nil {
		t.Fatal("expected redirect to be rejected")
	}
	if err := SendFailure(context.Background(), "ftp://invalid", payload); err == nil {
		t.Fatal("expected non-http scheme to be rejected")
	}
}
