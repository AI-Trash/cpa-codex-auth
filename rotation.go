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

type authenticatedAccount struct {
	client      *client.Client
	accessToken string
	email       string
	prompt      *prompter
}

type passwordReset struct {
	client      *client.Client
	email       string
	newPassword string
	prompt      *prompter
}

func rotateCredentials(ctx context.Context, account authenticatedAccount) (string, string, error) {
	info, err := getMFAInfo(ctx, account.client, account.accessToken)
	if err != nil {
		return "", "", err
	}
	if info.isEnabled() {
		factorID, factorErr := info.authenticatorFactorID()
		if factorErr != nil {
			return "", "", factorErr
		}
		if err := disableTOTP(ctx, mfaSession{client: account.client, accessToken: account.accessToken}, factorID); err != nil {
			return "", "", err
		}
	}

	newPassword, err := generatePassword()
	if err != nil {
		return "", "", err
	}
	if err := resetAccountPassword(ctx, passwordReset{client: account.client, email: account.email, newPassword: newPassword, prompt: account.prompt}); err != nil {
		return "", "", err
	}
	if _, err := fmt.Fprintf(account.prompt.output, "Generated password: %s\n", newPassword); err != nil {
		return "", "", fmt.Errorf("print generated password: %w", err)
	}

	loginClient, err := client.New(account.prompt.proxy)
	if err != nil {
		return "", "", fmt.Errorf("create post-rotation client: %w", err)
	}
	loginToken, _, _, err := authenticate(ctx, loginClient, account.email, newPassword, "", account.prompt)
	if err != nil {
		return "", "", fmt.Errorf("login after password rotation: %w", err)
	}
	accessToken, err := getChatGPTAccessToken(ctx, loginClient, loginToken.AccessToken)
	if err != nil {
		return "", "", err
	}
	newTOTPSecret, err := enrollTOTP(ctx, loginClient, accessToken)
	if err != nil {
		return "", "", err
	}
	if _, err := fmt.Fprintf(account.prompt.output, "Generated TOTP secret: %s\n", newTOTPSecret); err != nil {
		return "", "", fmt.Errorf("print generated TOTP secret: %w", err)
	}
	return newPassword, newTOTPSecret, nil
}

func resetAccountPassword(ctx context.Context, reset passwordReset) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/password/send-otp", nil)
	if err != nil {
		return fmt.Errorf("build password reset OTP request: %w", err)
	}
	setAuthMutationHeaders(req, authBaseURL+"/reset-password")
	resp, err := reset.client.Do(req)
	if err != nil {
		return fmt.Errorf("send password reset OTP: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("send password reset OTP failed: status %d", resp.StatusCode)
	}

	code, err := reset.prompt.askRequired("Password reset code for " + reset.email + ": ")
	if err != nil {
		return err
	}
	deviceID := reset.client.GetCookieValue("oai-did")
	sentinel, _, err := openai.BuildFullSentinelToken(reset.client, deviceID, "authorize_continue")
	if err != nil {
		return fmt.Errorf("create password reset sentinel: %w", err)
	}
	codeBody, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return fmt.Errorf("encode password reset code: %w", err)
	}
	state, err := postAuthJSON(ctx, reset.client, "/api/accounts/email-otp/validate", codeBody, authBaseURL+"/reset-password", sentinel, "")
	if err != nil {
		return err
	}
	if authState(state) != "reset_password_new_password" {
		return fmt.Errorf("password reset OTP returned unexpected state: %s", authState(state))
	}

	passwordBody, err := json.Marshal(map[string]string{"password": reset.newPassword})
	if err != nil {
		return fmt.Errorf("encode new password: %w", err)
	}
	resetReq, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/password/reset", strings.NewReader(string(passwordBody)))
	if err != nil {
		return fmt.Errorf("build password reset request: %w", err)
	}
	setAuthMutationHeaders(resetReq, authBaseURL+"/reset-password/new-password")
	resetResp, err := reset.client.Do(resetReq)
	if err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	defer resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resetResp.Body)
		if readErr != nil {
			return fmt.Errorf("reset password failed (%d) and response could not be read: %w", resetResp.StatusCode, readErr)
		}
		return fmt.Errorf("reset password failed (%d): %s", resetResp.StatusCode, string(body))
	}
	return nil
}

func setAuthMutationHeaders(req *http.Request, referer string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", authBaseURL)
	req.Header.Set("Referer", referer)
	req.Header.Set("User-Agent", client.UA)
}
