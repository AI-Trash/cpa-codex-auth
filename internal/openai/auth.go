package openai

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"openai-tool/cpa-codex-auth/internal/client"
)

// OAuth constants matching OpenAI's Codex flow.
const (
	AuthURL     = "https://auth.openai.com/oauth/authorize"
	TokenURL    = "https://auth.openai.com/oauth/token"
	SentinelURL = "https://sentinel.openai.com/backend-api/sentinel/req"
	ClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	RedirectURI = "http://localhost:1455/auth/callback"
	Scope       = "openid email profile offline_access"
)

// OAuthStart holds PKCE state for an OAuth authorization flow.
type OAuthStart struct {
	AuthURL      string
	State        string
	CodeVerifier string
	RedirectURI  string
}

// TokenResult holds the final token exchange result.
type TokenResult struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
	LastRefresh  string `json:"last_refresh"`
	Email        string `json:"email"`
	Type         string `json:"type"`
	Expired      string `json:"expired"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFAVerified  bool   `json:"mfa_verified,omitempty"`
}

// GenerateOAuthURL builds the PKCE authorize URL. Returns an error if the
// system CSPRNG cannot supply the state and verifier entropy required by PKCE.
func GenerateOAuthURL() (*OAuthStart, error) {
	state, err := randomURLSafe(16)
	if err != nil {
		return nil, fmt.Errorf("generate oauth state: %w", err)
	}
	verifier, err := randomURLSafe(64)
	if err != nil {
		return nil, fmt.Errorf("generate oauth verifier: %w", err)
	}
	challenge := sha256B64URL(verifier)

	params := url.Values{
		"client_id":                  {ClientID},
		"response_type":              {"code"},
		"redirect_uri":               {RedirectURI},
		"scope":                      {Scope},
		"state":                      {state},
		"code_challenge":             {challenge},
		"code_challenge_method":      {"S256"},
		"prompt":                     {"login"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
	}

	return &OAuthStart{
		AuthURL:      AuthURL + "?" + params.Encode(),
		State:        state,
		CodeVerifier: verifier,
		RedirectURI:  RedirectURI,
	}, nil
}

// BuildSentinelSOHeader builds the openai-sentinel-so-token header value.
func BuildSentinelSOHeader(token string) string {
	return fmt.Sprintf(`{"so":"%s"}`, token)
}

func FetchSentinelToken(c *client.Client, did, flow string) string {
	body := fmt.Sprintf(`{"p":"","id":"%s","flow":"%s"}`, did, flow)
	req, _ := http.NewRequest("POST", SentinelURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	req.Header.Set("Origin", "https://sentinel.openai.com")
	req.Header.Set("Referer", "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6")
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var result struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token
}

func BuildSentinelHeader(token, did string) string {
	return fmt.Sprintf(`{"p":"","t":"","c":"%s","id":"%s","flow":"authorize_continue"}`, token, did)
}

// ExchangeCodeForToken exchanges an authorization code for tokens.
func ExchangeCodeForToken(c *client.Client, codeValue, verifier, redirectURI string) (*TokenResult, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {ClientID},
		"code":          {codeValue},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}

	req, _ := http.NewRequest("POST", TokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if raw.RefreshToken == "" {
		return nil, fmt.Errorf("token exchange succeeded without refresh_token")
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("token exchange succeeded without access_token")
	}
	if raw.IDToken == "" {
		return nil, fmt.Errorf("token exchange succeeded without id_token")
	}

	claims := decodeJWTClaims(raw.IDToken)
	email, _ := claims["email"].(string)
	authClaims, _ := claims["https://api.openai.com/auth"].(map[string]any)
	accountID := ""
	if authClaims != nil {
		accountID, _ = authClaims["chatgpt_account_id"].(string)
	}

	now := time.Now().UTC()
	return &TokenResult{
		IDToken:      raw.IDToken,
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		AccountID:    accountID,
		LastRefresh:  now.Format(time.RFC3339),
		Email:        email,
		Type:         "codex",
		Expired:      now.Add(time.Duration(raw.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

// ExtractCallbackParams extracts code and state from a callback URL.
func ExtractCallbackParams(callbackURL string) (code, state string, err error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", "", err
	}
	code = u.Query().Get("code")
	state = u.Query().Get("state")
	if code == "" || state == "" {
		return "", "", fmt.Errorf("missing code or state in callback URL")
	}
	return code, state, nil
}

// DecodeJWTSegment decodes a single JWT segment (base64url, no verification).
func DecodeJWTSegment(seg string) map[string]any {
	// Add padding
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	data, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var result map[string]any
	json.Unmarshal(data, &result)
	return result
}

func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return nil
	}
	return DecodeJWTSegment(parts[1])
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256B64URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
