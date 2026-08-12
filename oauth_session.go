package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"openai-tool/cpa-codex-auth/internal/client"
	"openai-tool/cpa-codex-auth/internal/openai"
)

type oauthSession struct {
	start    *openai.OAuthStart
	deviceID string
}

type oauthInitializationResult struct {
	statusCode int
}

type oauthSessionOperations struct {
	initializeHTTP  func() (oauthInitializationResult, error)
	hasAuthSession  func() bool
	fallbackBrowser func() error
}

func initializeOAuthSession(c *client.Client) (oauthSession, error) {
	start, err := openai.GenerateOAuthURL()
	if err != nil {
		return oauthSession{}, fmt.Errorf("generate OAuth URL: %w", err)
	}
	deviceID := ensureDeviceID(c)
	if err := establishOAuthSession(oauthSessionOperations{
		initializeHTTP: func() (oauthInitializationResult, error) {
			return initializeOAuthSessionHTTP(c, start.AuthURL)
		},
		hasAuthSession: func() bool {
			return c.GetCookieValue("oai-client-auth-session") != ""
		},
		fallbackBrowser: func() error {
			return initializeOAuthSessionBrowser(c, start.AuthURL, deviceID)
		},
	}); err != nil {
		return oauthSession{}, fmt.Errorf("establish OAuth session: %w", err)
	}
	return oauthSession{start: start, deviceID: deviceID}, nil
}

func establishOAuthSession(operations oauthSessionOperations) error {
	result, httpErr := operations.initializeHTTP()
	if operations.hasAuthSession() {
		return nil
	}
	if err := operations.fallbackBrowser(); err != nil {
		if httpErr != nil {
			return fmt.Errorf("initialize OAuth session in browser after HTTP error: %w", err)
		}
		return fmt.Errorf("initialize OAuth session in browser after HTTP status %d: %w", result.statusCode, err)
	}
	if !operations.hasAuthSession() {
		return fmt.Errorf("OAuth browser initialization completed without oai-client-auth-session")
	}
	return nil
}

func initializeOAuthSessionHTTP(c *client.Client, authURL string) (oauthInitializationResult, error) {
	result := oauthInitializationResult{}
	current := authURL
	for range 10 {
		resp, requestErr := c.GetNoRedirect(current)
		if requestErr != nil {
			return result, fmt.Errorf("initialize OAuth: %w", requestErr)
		}
		result.statusCode = resp.StatusCode
		location := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			break
		}
		resolved, err := resolveLocation(current, location)
		if err != nil {
			return result, err
		}
		current = resolved
	}
	return result, nil
}

func ensureDeviceID(c *client.Client) string {
	if existing := c.GetCookieValue("oai-did"); existing != "" {
		return existing
	}
	deviceID := uuid.NewString()
	c.SetCookie(authBaseURL, "oai-did", deviceID)
	return deviceID
}

func completeOAuth(ctx context.Context, c *client.Client, session oauthSession) (tokenResult, error) {
	workspaceID := extractWorkspaceID(c.GetCookieValue("oai-client-auth-session"))
	if workspaceID == "" {
		return tokenResult{}, fmt.Errorf("authenticated session has no workspace ID")
	}
	body, err := json.Marshal(map[string]string{"workspace_id": workspaceID})
	if err != nil {
		return tokenResult{}, fmt.Errorf("encode workspace selection: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/workspace/select", strings.NewReader(string(body)))
	if err != nil {
		return tokenResult{}, fmt.Errorf("build workspace request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", authBaseURL)
	req.Header.Set("Referer", authBaseURL+"/sign-in-with-chatgpt/codex/consent")
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.Do(req)
	if err != nil {
		return tokenResult{}, fmt.Errorf("select workspace: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tokenResult{}, fmt.Errorf("select workspace failed: status %d", resp.StatusCode)
	}
	var selection struct {
		ContinueURL string `json:"continue_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&selection); err != nil {
		return tokenResult{}, fmt.Errorf("decode workspace selection: %w", err)
	}
	return followOAuthRedirects(c, selection.ContinueURL, session.start)
}

func followOAuthRedirects(c *client.Client, start string, oauth *openai.OAuthStart) (tokenResult, error) {
	current := start
	for range 10 {
		resp, err := c.GetNoRedirect(current)
		if err != nil {
			return tokenResult{}, fmt.Errorf("follow OAuth redirect: %w", err)
		}
		location := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || location == "" {
			break
		}
		resolved, err := resolveLocation(current, location)
		if err != nil {
			return tokenResult{}, err
		}
		if strings.Contains(resolved, "code=") && strings.Contains(resolved, "state=") {
			callback, parseErr := url.Parse(resolved)
			if parseErr != nil {
				return tokenResult{}, fmt.Errorf("parse OAuth callback: %w", parseErr)
			}
			if callback.Query().Get("state") != oauth.State {
				return tokenResult{}, fmt.Errorf("OAuth state mismatch")
			}
			token, exchangeErr := openai.ExchangeCodeForToken(c, callback.Query().Get("code"), oauth.CodeVerifier, oauth.RedirectURI)
			if exchangeErr != nil {
				return tokenResult{}, exchangeErr
			}
			return convertToken(token)
		}
		current = resolved
	}
	return tokenResult{}, fmt.Errorf("OAuth redirects did not contain an authorization code")
}

func convertToken(token *openai.TokenResult) (tokenResult, error) {
	expired, err := time.Parse(time.RFC3339, token.Expired)
	if err != nil {
		return tokenResult{}, fmt.Errorf("parse token expiration: %w", err)
	}
	lastRefresh, err := time.Parse(time.RFC3339, token.LastRefresh)
	if err != nil {
		return tokenResult{}, fmt.Errorf("parse token refresh time: %w", err)
	}
	return tokenResult{AccessToken: token.AccessToken, AccountID: token.AccountID, Email: token.Email, Expired: expired, IDToken: token.IDToken, LastRefresh: lastRefresh, RefreshToken: token.RefreshToken}, nil
}

func extractWorkspaceID(cookie string) string {
	parts := strings.Split(cookie, ".")
	if len(parts) == 0 {
		return ""
	}
	claims := openai.DecodeJWTSegment(parts[0])
	workspaces, ok := claims["workspaces"].([]any)
	if !ok || len(workspaces) == 0 {
		return ""
	}
	workspace, ok := workspaces[0].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := workspace["id"].(string)
	return id
}

func resolveLocation(current, location string) (string, error) {
	next, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse redirect location: %w", err)
	}
	if next.IsAbs() {
		return next.String(), nil
	}
	base, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("parse redirect base: %w", err)
	}
	return base.ResolveReference(next).String(), nil
}
