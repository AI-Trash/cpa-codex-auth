package main

import (
	"net/http"
	"testing"
)

func TestOAuthBrowserHeaders_excludesBrowserOwnedMetadata(t *testing.T) {
	// Given: a direct request with browser-owned metadata and application headers.
	headers := http.Header{
		"Accept":                   []string{"application/json"},
		"Content-Type":             []string{"application/json"},
		"Cookie":                   []string{"session=secret"},
		"Openai-Sentinel-Token":    []string{"sentinel"},
		"Openai-Sentinel-So-Token": []string{"so"},
		"Origin":                   []string{authBaseURL},
		"Referer":                  []string{authBaseURL + "/log-in"},
		"Sec-Fetch-Site":           []string{"same-origin"},
		"User-Agent":               []string{"direct-client"},
	}

	// When: headers are prepared for browser fetch.
	filtered := filterOAuthBrowserHeaders(headers)

	// Then: the browser owns identity metadata while application headers survive.
	if filtered["Accept"] != "application/json" || filtered["Content-Type"] != "application/json" || filtered["Openai-Sentinel-Token"] != "sentinel" || filtered["Openai-Sentinel-So-Token"] != "so" {
		t.Fatalf("application headers = %#v", filtered)
	}
	for _, name := range []string{"Cookie", "Origin", "Referer", "Sec-Fetch-Site", "User-Agent"} {
		if _, ok := filtered[name]; ok {
			t.Fatalf("browser-owned header %q was forwarded", name)
		}
	}
}

func TestBrowserFetchStatus_returnsFoundForOpaqueManualRedirect(t *testing.T) {
	// Given: fetch reports the browser-defined opaque redirect status for a no-redirect request.
	const opaqueRedirectStatus = 0

	// When: its response is converted to the client's no-redirect contract.
	status := browserFetchStatus(opaqueRedirectStatus, false)

	// Then: email OTP handling receives a redirect status it accepts without navigating.
	if status != http.StatusFound {
		t.Fatalf("manual redirect status = %d, want %d", status, http.StatusFound)
	}
}
