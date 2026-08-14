package openai

import (
	"net/http"
	"strings"
	"testing"
)

func TestSentinelBrowserScript_non200ErrorOmitsResponseBody(t *testing.T) {
	// Given: a synthetic browser response with a challenge document body.
	challengeBody := "<html>Cloudflare challenge document</html>"
	status := http.StatusForbidden
	script, err := sentinelBrowserScript("request-body")
	if err != nil {
		t.Fatalf("sentinelBrowserScript() error = %v", err)
	}

	// When: the browser evaluates its non-200 failure branch.
	// Then: the error carries machine status only, not the response body.
	if !strings.Contains(script, "'HTTP ' + request.status") {
		t.Fatalf("script does not include HTTP status: %s", script)
	}
	if strings.Contains(script, "request.status + ': ' + request.responseText") {
		t.Fatalf("status %d error exposes response body %q", status, challengeBody)
	}
}
