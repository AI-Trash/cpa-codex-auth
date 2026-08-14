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

type credentialRotationRequest struct {
	account     authenticatedAccount
	info        mfaInfo
	newPassword string
}

type credentialRotationOperations struct {
	disableTOTP   func(context.Context, mfaSession, string) error
	enrollTOTP    func(context.Context, *client.Client, string) (string, error)
	resetPassword func(context.Context, passwordReset) error
}

func rotateCredentials(ctx context.Context, account authenticatedAccount) (string, string, error) {
	info, err := getMFAInfo(ctx, account.client, account.accessToken)
	if err != nil {
		return "", "", err
	}
	newPassword, err := generatePassword()
	if err != nil {
		return "", "", err
	}
	newTOTPSecret, err := executeCredentialRotation(ctx, credentialRotationRequest{
		account:     account,
		info:        info,
		newPassword: newPassword,
	}, credentialRotationOperations{
		disableTOTP:   disableTOTP,
		enrollTOTP:    enrollTOTP,
		resetPassword: resetAccountPassword,
	})
	if err != nil {
		return "", "", err
	}
	if _, err := fmt.Fprintf(account.prompt.output, "Generated password: %s\n", newPassword); err != nil {
		return "", "", fmt.Errorf("print generated password: %w", err)
	}
	return newPassword, newTOTPSecret, nil
}

func executeCredentialRotation(ctx context.Context, request credentialRotationRequest, operations credentialRotationOperations) (string, error) {
	if request.info.isEnabled() {
		factorID, err := request.info.authenticatorFactorID()
		if err != nil {
			return "", err
		}
		if err := operations.disableTOTP(ctx, mfaSession{client: request.account.client, accessToken: request.account.accessToken}, factorID); err != nil {
			return "", err
		}
	}
	newTOTPSecret, err := operations.enrollTOTP(ctx, request.account.client, request.account.accessToken)
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(request.account.prompt.output, "Generated TOTP secret: %s\n", newTOTPSecret); err != nil {
		return "", fmt.Errorf("print generated TOTP secret: %w", err)
	}
	if err := operations.resetPassword(ctx, passwordReset{
		client:      request.account.client,
		email:       request.account.email,
		newPassword: request.newPassword,
		prompt:      request.account.prompt,
	}); err != nil {
		return "", err
	}
	return newTOTPSecret, nil
}

func resetAccountPassword(ctx context.Context, reset passwordReset) error {
	deviceID := reset.client.GetCookieValue("oai-did")
	sentinel, _, err := openai.BuildFullSentinelToken(reset.client, deviceID, "authorize_continue")
	if err != nil {
		return fmt.Errorf("create password reset sentinel: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authBaseURL+"/api/accounts/password/send-otp", nil)
	if err != nil {
		return fmt.Errorf("build password reset OTP request: %w", err)
	}
	setAuthMutationHeaders(req, authBaseURL+"/reset-password")
	req.Header.Set("openai-sentinel-token", sentinel)
	resp, err := reset.client.Do(req)
	if err != nil {
		return fmt.Errorf("send password reset OTP: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("send password reset OTP failed (%d) and response could not be read: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("send password reset OTP failed (%d): %s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	code, err := reset.prompt.askRequired("Password reset code for " + reset.email + ": ")
	if err != nil {
		return err
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
