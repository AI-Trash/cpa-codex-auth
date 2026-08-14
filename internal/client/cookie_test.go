package client

import (
	"io"
	"net/http"
	"testing"
	"time"
)

type recordingAuthTransport struct {
	urls []string
}

func (t *recordingAuthTransport) HandleAuthRequest(request *http.Request, _ bool, _ AuthDirect) (*http.Response, error) {
	t.urls = append(t.urls, request.URL.String())
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(http.NoBody)}, nil
}

func TestClientCookies_preservesHTTPOnlyForBrowserSynchronization(t *testing.T) {
	// Given: an HttpOnly auth cookie imported from a browser session.
	c, err := New("")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	c.StoreCookie("https://auth.openai.com", Cookie{
		Name:     "oai-client-auth-session",
		Value:    "session-value",
		Domain:   "auth.openai.com",
		Path:     "/",
		HTTPOnly: true,
		Secure:   true,
	})

	// When: cookies are exported to restore the persistent browser context.
	cookies := c.CookiesForURL("https://auth.openai.com/api/accounts")

	// Then: the browser-only flag and scope survive the round trip.
	if len(cookies) != 1 {
		t.Fatalf("cookies = %#v, want one cookie", cookies)
	}
	if !cookies[0].HTTPOnly || !cookies[0].Secure || cookies[0].Path != "/" {
		t.Fatalf("cookie scope = %#v, want HttpOnly secure root cookie", cookies[0])
	}
}

func TestClientCookies_preservesBrowserLifetimeAttributes(t *testing.T) {
	// Given: a browser cookie whose SameSite policy and expiry affect Cloudflare behavior.
	expires := time.Unix(1_800_000_000, 0).UTC()
	c, err := New("")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	c.StoreCookie("https://auth.openai.com", Cookie{
		Name:     "cf_clearance",
		Value:    "clearance",
		Domain:   "auth.openai.com",
		Path:     "/",
		SameSite: "None",
		Expires:  &expires,
		Secure:   true,
	})

	// When: the cookie is exported for the persistent browser.
	cookies := c.CookiesForURL("https://auth.openai.com/api/accounts")

	// Then: browser-controlled lifetime attributes remain intact.
	if len(cookies) != 1 || cookies[0].SameSite != "None" || cookies[0].Expires == nil || !cookies[0].Expires.Equal(expires) {
		t.Fatalf("browser attributes = %#v", cookies)
	}
}

func TestClientAuthTransport_routesEveryAuthOpenAIRequest(t *testing.T) {
	// Given: a client with a session-owned auth transport.
	c, err := New("")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	transport := &recordingAuthTransport{}
	c.SetAuthTransport(transport)
	urls := []string{
		"https://auth.openai.com/api/accounts/authorize/continue",
		"https://auth.openai.com/api/accounts/email-otp/send",
		"https://auth.openai.com/api/accounts/client_auth_session_dump",
		"https://auth.openai.com/api/accounts/workspace/select",
	}

	// When: auth front-channel routes execute through the shared client.
	for _, rawURL := range urls {
		req, requestErr := http.NewRequest(http.MethodGet, rawURL, nil)
		if requestErr != nil {
			t.Fatalf("build request: %v", requestErr)
		}
		response, requestErr := c.Do(req)
		if requestErr != nil {
			t.Fatalf("send request: %v", requestErr)
		}
		response.Body.Close()
	}

	// Then: every auth.openai.com route is delegated before direct HTTP execution.
	if len(transport.urls) != len(urls) {
		t.Fatalf("transport URLs = %#v, want %#v", transport.urls, urls)
	}
}
