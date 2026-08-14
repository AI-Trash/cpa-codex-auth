package openai

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestFetchSentinelChallenge_whenHTTPIsBlocked_usesHeadlessBrowser(t *testing.T) {
	// Given: the fingerprinted HTTP request is rejected by Cloudflare.
	browserCalls := 0
	httpFetch := func() (int, []byte, error) {
		return http.StatusForbidden, []byte("blocked"), nil
	}
	browserFetch := func() ([]byte, error) {
		browserCalls++
		return []byte(`{"token":"browser-token"}`), nil
	}

	// When: the Sentinel challenge is fetched.
	body, err := fetchSentinelChallenge(httpFetch, browserFetch)

	// Then: the real headless-browser result is returned.
	if err != nil {
		t.Fatalf("fetchSentinelChallenge() error = %v", err)
	}
	if got, want := string(body), `{"token":"browser-token"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if browserCalls != 1 {
		t.Fatalf("browser calls = %d, want 1", browserCalls)
	}
}

func TestFetchSentinelChallenge_whenHTTPWorks_skipsHeadlessBrowser(t *testing.T) {
	// Given: the fingerprinted HTTP request succeeds.
	browserCalls := 0
	httpFetch := func() (int, []byte, error) {
		return http.StatusOK, []byte(`{"token":"http-token"}`), nil
	}
	browserFetch := func() ([]byte, error) {
		browserCalls++
		return nil, errors.New("browser should not run")
	}

	// When: the Sentinel challenge is fetched.
	body, err := fetchSentinelChallenge(httpFetch, browserFetch)

	// Then: the HTTP result is retained without starting Chrome.
	if err != nil {
		t.Fatalf("fetchSentinelChallenge() error = %v", err)
	}
	if got, want := string(body), `{"token":"http-token"}`; got != want {
		t.Fatalf("body = %s, want %s", got, want)
	}
	if browserCalls != 0 {
		t.Fatalf("browser calls = %d, want 0", browserCalls)
	}
}

func TestFetchSentinelChallenge_whenHTMLFails_doesNotExposeTheDocument(t *testing.T) {
	// Given: a non-retriable HTML response from the Sentinel endpoint.
	html := "<html>Cloudflare challenge document</html>"
	httpFetch := func() (int, []byte, error) {
		return http.StatusBadGateway, []byte(html), nil
	}

	// When: the Sentinel request fails.
	_, err := fetchSentinelChallenge(httpFetch, func() ([]byte, error) { return nil, errors.New("browser should not run") })

	// Then: the bounded diagnostic identifies the status without returning server HTML.
	if err == nil {
		t.Fatal("fetchSentinelChallenge unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), html) || strings.Contains(strings.ToLower(err.Error()), "<html") {
		t.Fatalf("error exposed HTML: %v", err)
	}
}
