package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"openai-tool/cpa-codex-auth/internal/openai"
)

type fakeOAuthBrowser struct {
	fetches  []oauthBrowserFetchRequest
	redirect oauthBrowserRedirectRequest
	callback string
	response *http.Response
}

func (b *fakeOAuthBrowser) Fetch(_ context.Context, request oauthBrowserFetchRequest) (*http.Response, error) {
	b.fetches = append(b.fetches, request)
	if b.response != nil {
		return b.response, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"page":{"type":"ready"}}`)),
	}, nil
}

func TestOAuthSession_rejectsBrowserManagedChallengeWithoutHTML(t *testing.T) {
	// Given: the browser retry itself receives a managed challenge page.
	browser := &fakeOAuthBrowser{response: &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Cf-Mitigated": []string{"challenge"}},
		Body:       io.NopCloser(bytes.NewBufferString("<html>managed challenge response</html>")),
	}}
	session := &oauthSession{browser: browser}

	// When: the session consumes the browser response.
	_, err := session.fetchInBrowser(context.Background(), oauthBrowserFetchRequest{URL: authBaseURL + "/api/accounts/authorize/continue"})

	// Then: callers receive a typed bounded error, never the challenge document.
	if !errors.Is(err, ErrManagedChallenge) {
		t.Fatalf("error = %v, want managed challenge", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "<html") || len(err.Error()) > 128 {
		t.Fatalf("error leaked or exceeded bound: %v", err)
	}
}

func (b *fakeOAuthBrowser) FollowRedirects(_ context.Context, request oauthBrowserRedirectRequest) (string, error) {
	b.redirect = request
	return b.callback, nil
}

func (b *fakeOAuthBrowser) Close() {}

func TestOAuthSession_usesBrowserForChallengedAndFutureAuthRequests(t *testing.T) {
	// Given: the first direct auth request receives a Cloudflare managed challenge.
	browser := &fakeOAuthBrowser{}
	session := &oauthSession{
		start: &openai.OAuthStart{AuthURL: authBaseURL + "/oauth/authorize", RedirectURI: "http://localhost:1455/auth/callback"},
		newBrowser: func(context.Context, oauthBrowserLaunchRequest) (oauthBrowser, error) {
			return browser, nil
		},
	}
	directCalls := 0
	direct := func(*http.Request, bool) (*http.Response, error) {
		directCalls++
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header: http.Header{
				"Cf-Mitigated": []string{"challenge"},
				"Content-Type": []string{"text/html"},
			},
			Body: io.NopCloser(bytes.NewBufferString("<html>challenge</html>")),
		}, nil
	}
	first, err := http.NewRequestWithContext(context.Background(), http.MethodPost, authBaseURL+"/api/accounts/authorize/continue", nil)
	if err != nil {
		t.Fatalf("build first request: %v", err)
	}
	second, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authBaseURL+"/api/accounts/client_auth_session_dump", nil)
	if err != nil {
		t.Fatalf("build second request: %v", err)
	}

	// When: the challenged request and a later state request are sent.
	firstResponse, err := session.HandleAuthRequest(first, true, direct)
	if err != nil {
		t.Fatalf("handle challenged request: %v", err)
	}
	firstResponse.Body.Close()
	secondResponse, err := session.HandleAuthRequest(second, true, direct)
	if err != nil {
		t.Fatalf("handle sticky browser request: %v", err)
	}
	secondResponse.Body.Close()

	// Then: the original request retries in one browser and all future auth requests stay there.
	if directCalls != 1 {
		t.Fatalf("direct calls = %d, want 1", directCalls)
	}
	if len(browser.fetches) != 2 {
		t.Fatalf("browser fetches = %d, want 2", len(browser.fetches))
	}
	if got := browser.fetches[0].URL; got != first.URL.String() {
		t.Fatalf("first browser URL = %q, want %q", got, first.URL)
	}
	if got := browser.fetches[1].URL; got != second.URL.String() {
		t.Fatalf("second browser URL = %q, want %q", got, second.URL)
	}
}

func TestOAuthSession_followsBrowserCallbackAndExchangesOnlyItsCode(t *testing.T) {
	// Given: browser-backed OAuth redirect completion and a matching localhost callback.
	browser := &fakeOAuthBrowser{callback: "http://localhost:1455/auth/callback?code=browser-code&state=expected-state"}
	exchangeCalls := 0
	session := &oauthSession{
		start:         &openai.OAuthStart{State: "expected-state", RedirectURI: "http://localhost:1455/auth/callback"},
		browser:       browser,
		browserActive: true,
		exchange: func(request oauthTokenExchangeRequest) (tokenResult, error) {
			exchangeCalls++
			if request.Code != "browser-code" || request.State != "expected-state" {
				t.Fatalf("callback exchange = %#v", request)
			}
			return tokenResult{AccessToken: "access"}, nil
		},
	}

	// When: the browser completes the redirect chain.
	token, err := session.followOAuthRedirects(context.Background(), authBaseURL+"/continue")

	// Then: the exact callback URI/state are captured and token exchange stays outside the browser.
	if err != nil {
		t.Fatalf("follow browser redirects: %v", err)
	}
	if token.AccessToken != "access" {
		t.Fatalf("access token = %q, want access", token.AccessToken)
	}
	if exchangeCalls != 1 {
		t.Fatalf("token exchange calls = %d, want 1", exchangeCalls)
	}
	if browser.redirect.RedirectURI != session.start.RedirectURI {
		t.Fatalf("redirect URI = %q, want %q", browser.redirect.RedirectURI, session.start.RedirectURI)
	}
}

func TestManagedChallenge_detectsHTMLMarkersAfterCheckingCFMitigated(t *testing.T) {
	// Given: a 403 HTML response carrying a Cloudflare challenge marker.
	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}

	// When: the response is classified for browser fallback.
	managed := isManagedChallenge(response, []byte("<html><div id=cf-chl-widget></div></html>"))

	// Then: the marker is sufficient even without a cf-mitigated response header.
	if !managed {
		t.Fatal("managed challenge was not detected")
	}
}

func TestManagedChallenge_detectsCloudflareJavaScriptCookieInterstitial(t *testing.T) {
	// Given: the canonical Cloudflare interstitial returned by password verification.
	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
	}

	// When: the response is classified for browser fallback.
	managed := isManagedChallenge(response, []byte("<html><body>Enable JavaScript and cookies to continue</body></html>"))

	// Then: the interstitial activates the persistent browser path.
	if !managed {
		t.Fatal("Cloudflare JavaScript and cookie interstitial was not detected")
	}
}

func TestAuthenticateSession_keepsFrontChannelStateTransitionsInTheBrowser(t *testing.T) {
	// Given: the email continuation is challenged and the remaining state transitions are successful.
	browser := &fakeOAuthBrowser{callback: "http://localhost:1455/auth/callback?code=browser-code&state=expected-state"}
	session := &oauthSession{
		start: &openai.OAuthStart{State: "expected-state", RedirectURI: "http://localhost:1455/auth/callback"},
		newBrowser: func(context.Context, oauthBrowserLaunchRequest) (oauthBrowser, error) {
			return browser, nil
		},
		exchange: func(oauthTokenExchangeRequest) (tokenResult, error) {
			return tokenResult{AccessToken: "access"}, nil
		},
	}
	direct := func(*http.Request, bool) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     http.Header{"Cf-Mitigated": []string{"challenge"}},
			Body:       io.NopCloser(bytes.NewBufferString("<html>challenge</html>")),
		}, nil
	}
	operations := authenticationOperations{
		submitEmail: func(ctx context.Context, request authenticationEmailRequest) (authResponse, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/authorize/continue", nil)
			if err != nil {
				return authResponse{}, err
			}
			response, err := request.Session.HandleAuthRequest(req, true, direct)
			if err != nil {
				return authResponse{}, err
			}
			response.Body.Close()
			return authResponse{Page: struct {
				Type    string `json:"type"`
				Payload struct {
					FactorID string `json:"factor_id"`
				} `json:"payload"`
			}{Type: "login_password"}}, nil
		},
		verifyPassword: func(ctx context.Context, request authenticationPasswordRequest) (authResponse, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/password/verify", nil)
			if err != nil {
				return authResponse{}, err
			}
			response, err := request.Session.HandleAuthRequest(req, true, direct)
			if err != nil {
				return authResponse{}, err
			}
			response.Body.Close()
			return authResponse{}, nil
		},
		fetchAuthState: func(ctx context.Context, session *oauthSession, _ string) (authResponse, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, authBaseURL+"/api/accounts/client_auth_session_dump", nil)
			if err != nil {
				return authResponse{}, err
			}
			response, err := session.HandleAuthRequest(req, true, direct)
			if err != nil {
				return authResponse{}, err
			}
			response.Body.Close()
			return authResponse{}, nil
		},
		completeOAuth: func(ctx context.Context, session *oauthSession) (tokenResult, error) {
			return session.followOAuthRedirects(ctx, authBaseURL+"/continue")
		},
	}

	// When: the real authentication state-loop shape advances to OAuth completion.
	token, _, _, err := authenticateSession(context.Background(), authenticationRequest{
		Session:  session,
		Email:    "user@example.com",
		Password: "password",
	}, operations)

	// Then: email, password, state refresh, and callback completion use the same browser session.
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	if token.AccessToken != "access" {
		t.Fatalf("access token = %q, want access", token.AccessToken)
	}
	if len(browser.fetches) != 3 {
		t.Fatalf("browser fetches = %d, want 3", len(browser.fetches))
	}
	if browser.redirect.URL != authBaseURL+"/continue" {
		t.Fatalf("redirect start = %q, want OAuth continuation", browser.redirect.URL)
	}
}
