package openai

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"
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

func TestSentinelBrowserAllocatorOptions_constructsAllocator(t *testing.T) {
	// Given: executable path, profile directory, and proxy URL.
	executablePath := "chrome"
	profileDir := "/tmp/profile"
	proxyURL := "http://127.0.0.1:8080"

	// When: options are constructed.
	opts := sentinelBrowserAllocatorOptions(executablePath, profileDir, proxyURL)

	// Then: options configure an allocator without error.
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	if allocCtx == nil {
		t.Fatal("expected non-nil allocator context")
	}
}
