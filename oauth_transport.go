package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"openai-tool/cpa-codex-auth/internal/client"
)

var ErrManagedChallenge = errors.New("managed challenge")

type managedChallengeError struct {
	statusCode int
}

func (e managedChallengeError) Error() string {
	return fmt.Sprintf("managed challenge: status %d", e.statusCode)
}

func (e managedChallengeError) Is(target error) bool {
	return target == ErrManagedChallenge
}

type oauthBrowser interface {
	Fetch(context.Context, oauthBrowserFetchRequest) (*http.Response, error)
	FollowRedirects(context.Context, oauthBrowserRedirectRequest) (string, error)
	Close()
}

type oauthBrowserLaunchRequest struct {
	Client   *client.Client
	AuthURL  string
	DeviceID string
}

type oauthBrowserFetchRequest struct {
	Method          string
	URL             string
	Header          http.Header
	Body            []byte
	FollowRedirects bool
}

type oauthBrowserRedirectRequest struct {
	URL         string
	RedirectURI string
}

type oauthTokenExchangeRequest struct {
	Code         string
	State        string
	CodeVerifier string
	RedirectURI  string
}

type oauthBrowserFactory func(context.Context, oauthBrowserLaunchRequest) (oauthBrowser, error)

func (s *oauthSession) HandleAuthRequest(request *http.Request, followRedirects bool, direct client.AuthDirect) (*http.Response, error) {
	if request.URL.Path == "/oauth/token" {
		return direct(request, followRedirects)
	}
	body, err := readAuthRequestBody(request)
	if err != nil {
		return nil, err
	}
	browserRequest := oauthBrowserFetchRequest{
		Method:          request.Method,
		URL:             request.URL.String(),
		Header:          request.Header.Clone(),
		Body:            body,
		FollowRedirects: followRedirects,
	}
	if s.browserActive {
		return s.fetchInBrowser(request.Context(), browserRequest)
	}
	directRequest := request.Clone(request.Context())
	directRequest.Body = io.NopCloser(bytes.NewReader(body))
	response, err := direct(directRequest, followRedirects)
	if err != nil {
		return nil, err
	}
	responseBody, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close auth response: %w", closeErr)
	}
	if !isManagedChallenge(response, responseBody) {
		response.Body = io.NopCloser(bytes.NewReader(responseBody))
		return response, nil
	}
	if err := s.activateBrowser(request.Context()); err != nil {
		return nil, fmt.Errorf("activate browser for managed challenge: %w", err)
	}
	return s.fetchInBrowser(request.Context(), browserRequest)
}

func (s *oauthSession) activateBrowser(ctx context.Context) error {
	if err := s.ensureBrowser(ctx); err != nil {
		return err
	}
	s.browserActive = true
	return nil
}

func (s *oauthSession) ensureBrowser(ctx context.Context) error {
	if s.browser != nil {
		return nil
	}
	factory := s.newBrowser
	if factory == nil {
		factory = launchOAuthBrowser
	}
	browser, err := factory(ctx, oauthBrowserLaunchRequest{
		Client:   s.client,
		AuthURL:  s.start.AuthURL,
		DeviceID: s.deviceID,
	})
	if err != nil {
		return err
	}
	s.browser = browser
	return nil
}

func (s *oauthSession) fetchInBrowser(ctx context.Context, request oauthBrowserFetchRequest) (*http.Response, error) {
	response, err := s.browser.Fetch(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("browser auth request: %w", err)
	}
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read browser auth response: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close browser auth response: %w", closeErr)
	}
	if isManagedChallenge(response, body) {
		return nil, managedChallengeError{statusCode: response.StatusCode}
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func (s *oauthSession) Close() {
	if s.client != nil {
		s.client.SetAuthTransport(nil)
	}
	if s.browser != nil {
		s.browser.Close()
	}
}

func readAuthRequestBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(request.Body)
	if closeErr := request.Body.Close(); closeErr != nil && err == nil {
		err = fmt.Errorf("close auth request body: %w", closeErr)
	}
	if err != nil {
		return nil, fmt.Errorf("read auth request body: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func isManagedChallenge(response *http.Response, body []byte) bool {
	if response.Header.Get("cf-mitigated") != "" {
		return true
	}
	if response.StatusCode != http.StatusForbidden || !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
		return false
	}
	content := strings.ToLower(string(body))
	return strings.Contains(content, "cf-chl") || strings.Contains(content, "challenge-platform") || strings.Contains(content, "just a moment")
}
