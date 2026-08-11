package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"openai-tool/cpa-codex-auth/internal/client"
	"openai-tool/cpa-codex-auth/internal/openai"
)

func handleEmailVerification(ctx context.Context, c *client.Client, deviceID, email string, prompt *prompter) (authResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authBaseURL+"/api/accounts/email-otp/send", nil)
	if err != nil {
		return authResponse{}, fmt.Errorf("build email OTP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", authBaseURL+"/create-account/password")
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.DoNoRedirect(req)
	if err != nil {
		return authResponse{}, fmt.Errorf("send email OTP: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return authResponse{}, fmt.Errorf("send email OTP failed: status %d", resp.StatusCode)
	}
	code, err := prompt.askRequired("Email verification code for " + email + ": ")
	if err != nil {
		return authResponse{}, err
	}
	sentinel, _, err := openai.BuildFullSentinelToken(c, deviceID, "authorize_continue")
	if err != nil {
		return authResponse{}, fmt.Errorf("create email OTP sentinel: %w", err)
	}
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode email OTP: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/email-otp/validate", body, authBaseURL+"/email-verification", sentinel, "")
}

func handlePhoneVerification(ctx context.Context, c *client.Client, prompt *prompter) (authResponse, error) {
	phone, err := prompt.askRequired("Phone number in E.164 format (for example +14155552671): ")
	if err != nil {
		return authResponse{}, err
	}
	if !strings.HasPrefix(phone, "+") {
		return authResponse{}, fmt.Errorf("phone number must start with + and country code")
	}
	body, err := json.Marshal(map[string]string{"phone_number": phone})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode phone number: %w", err)
	}
	response, err := postAuthJSON(ctx, c, "/api/accounts/add-phone/send", body, authBaseURL+"/add-phone", "", "")
	if err != nil {
		return authResponse{}, err
	}
	if authState(response) == "phone_channel" {
		channelBody, marshalErr := json.Marshal(map[string]string{"channel": "sms"})
		if marshalErr != nil {
			return authResponse{}, fmt.Errorf("encode phone channel: %w", marshalErr)
		}
		response, err = postAuthJSON(ctx, c, "/api/accounts/phone-otp/send", channelBody, authBaseURL+"/phone-otp/select-channel", "", "")
		if err != nil {
			return authResponse{}, err
		}
	}
	code, err := prompt.askRequired("Phone SMS verification code: ")
	if err != nil {
		return authResponse{}, err
	}
	codeBody, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode phone OTP: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/phone-otp/validate", codeBody, authBaseURL+"/phone-verification", "", "")
}

func createProfile(ctx context.Context, c *client.Client, deviceID string) (authResponse, error) {
	sentinel, challenge, err := openai.BuildFullSentinelToken(c, deviceID, "oauth_create_account")
	if err != nil {
		return authResponse{}, fmt.Errorf("create profile sentinel: %w", err)
	}
	body, err := json.Marshal(map[string]string{"name": "Codex User", "birthdate": "1990-01-01"})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode profile: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/create_account", body, authBaseURL+"/about-you", sentinel, openai.BuildSentinelSOHeader(challenge))
}
