package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"openai-tool/cpa-codex-auth/internal/client"
)

type authResponseTransport struct{}

func (authResponseTransport) HandleAuthRequest(*http.Request, bool, client.AuthDirect) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Header: http.Header{
			authTransportSourceHeader: []string{authTransportSourceDirect},
			"Content-Type":            []string{"text/html; charset=UTF-8"},
			"Server":                  []string{"cloudflare"},
			"Cf-Ray":                  []string{"ray-id"},
		},
		Body: io.NopCloser(strings.NewReader("<html>sensitive challenge body</html>")),
	}, nil
}

func TestPostAuthJSON_reportsSanitizedResponseMetadata(t *testing.T) {
	// Given: a direct Cloudflare response whose body must remain private.
	c := &client.Client{}
	c.SetAuthTransport(authResponseTransport{})

	// When: the auth request fails.
	_, err := postAuthJSON(context.Background(), c, "/api/accounts/password/verify", []byte(`{"password":"secret"}`), authBaseURL, "", "")

	// Then: the error identifies the route and response fingerprint without body text.
	if err == nil {
		t.Fatal("postAuthJSON unexpectedly succeeded")
	}
	message := err.Error()
	for _, field := range []string{"source=\"direct\"", "status=403", "content_type=\"text/html; charset=UTF-8\"", "server=\"cloudflare\"", "cf_ray=\"ray-id\"", "body_bytes=37", "body_sha256="} {
		if !strings.Contains(message, field) {
			t.Fatalf("error %q missing %q", message, field)
		}
	}
	if strings.Contains(message, "sensitive challenge body") || strings.Contains(message, "secret") {
		t.Fatalf("error leaked sensitive content: %q", message)
	}
}
