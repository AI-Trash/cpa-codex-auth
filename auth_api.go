package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"openai-tool/cpa-codex-auth/internal/client"
	"openai-tool/cpa-codex-auth/internal/openai"
)

const authBaseURL = "https://auth.openai.com"

type authResponse struct {
	ContinueURL string `json:"continue_url"`
	Page        struct {
		Type    string `json:"type"`
		Payload struct {
			FactorID string `json:"factor_id"`
		} `json:"payload"`
	} `json:"page"`
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func submitEmail(ctx context.Context, c *client.Client, deviceID, email string) (authResponse, error) {
	sentinel, _, err := openai.BuildFullSentinelToken(c, deviceID, "authorize_continue")
	if err != nil {
		return authResponse{}, fmt.Errorf("create email sentinel: %w", err)
	}
	body, err := json.Marshal(map[string]any{"username": map[string]string{"kind": "email", "value": email}})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode email request: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/authorize/continue", body, authBaseURL+"/log-in", sentinel, "")
}

func verifyPassword(ctx context.Context, c *client.Client, deviceID, password string) (authResponse, error) {
	sentinel, _, err := openai.BuildFullSentinelToken(c, deviceID, "password_verify")
	if err != nil {
		return authResponse{}, fmt.Errorf("create password sentinel: %w", err)
	}
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode password request: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/password/verify", body, authBaseURL+"/log-in/password", sentinel, "")
}

func createPassword(ctx context.Context, c *client.Client, deviceID, email, password string) (authResponse, error) {
	sentinel, _, err := openai.BuildFullSentinelToken(c, deviceID, "username_password_create")
	if err != nil {
		return authResponse{}, fmt.Errorf("create password sentinel: %w", err)
	}
	body, err := json.Marshal(map[string]string{"password": password, "username": email})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode password creation request: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/user/register", body, authBaseURL+"/create-account/password", sentinel, "")
}

func postAuthJSON(ctx context.Context, c *client.Client, path string, body []byte, referer, sentinel, soToken string) (authResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+path, strings.NewReader(string(body)))
	if err != nil {
		return authResponse{}, fmt.Errorf("build auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", authBaseURL)
	req.Header.Set("Referer", referer)
	req.Header.Set("User-Agent", client.UA)
	if sentinel != "" {
		req.Header.Set("Openai-Sentinel-Token", sentinel)
	}
	if soToken != "" {
		req.Header.Set("Openai-Sentinel-So-Token", soToken)
	}
	resp, err := c.Do(req)
	if err != nil {
		return authResponse{}, fmt.Errorf("send auth request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return authResponse{}, fmt.Errorf("read auth response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return authResponse{}, fmt.Errorf("auth request %s failed (%d): %s", path, resp.StatusCode, string(responseBody))
	}
	var result authResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return authResponse{}, fmt.Errorf("decode auth response: %w", err)
	}
	return result, nil
}

func fetchAuthState(ctx context.Context, c *client.Client, referer string) (authResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authBaseURL+"/api/accounts/client_auth_session_dump", nil)
	if err != nil {
		return authResponse{}, fmt.Errorf("build session request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", referer)
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.Do(req)
	if err != nil {
		return authResponse{}, fmt.Errorf("fetch auth state: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authResponse{}, fmt.Errorf("fetch auth state failed: status %d", resp.StatusCode)
	}
	var result authResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return authResponse{}, fmt.Errorf("decode auth state: %w", err)
	}
	return result, nil
}

func authState(response authResponse) string {
	if response.Page.Type != "" {
		return response.Page.Type
	}
	switch {
	case strings.Contains(response.ContinueURL, "add-phone"):
		return "add_phone"
	case strings.Contains(response.ContinueURL, "phone-otp/select-channel"):
		return "phone_channel"
	case strings.Contains(response.ContinueURL, "phone-verification"):
		return "phone_verification"
	case strings.Contains(response.ContinueURL, "about-you"):
		return "about_you"
	case response.Error.Code != "":
		return "error:" + response.Error.Code
	case response.Error.Type != "":
		return "error:" + response.Error.Type
	default:
		return "ready"
	}
}
