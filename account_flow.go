package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"openai-tool/cpa-codex-auth/internal/client"
)

type postAccountSetupOperations struct {
	authenticateFinal func() (tokenResult, error)
	save              func(tokenResult) error
}

func finalizeCodexAuthentication(firstToken tokenResult, rotate bool, operations postAccountSetupOperations) error {
	token := firstToken
	if rotate {
		finalToken, err := operations.authenticateFinal()
		if err != nil {
			return fmt.Errorf("final Codex OAuth: %w", err)
		}
		token = finalToken
	}
	return operations.save(token)
}

func runAuthentication(ctx context.Context, credentials startupCredentials, prompt *prompter) error {
	if credentials.email == "" {
		return fmt.Errorf("email is required")
	}
	firstClient, err := client.New(prompt.proxy)
	if err != nil {
		return fmt.Errorf("create login client: %w", err)
	}
	password := credentials.password
	totpSecret := credentials.totpSecret
	firstToken, password, totpSecret, err := authenticate(ctx, firstClient, credentials.email, password, totpSecret, prompt)
	if err != nil {
		return err
	}
	accessToken, err := getChatGPTAccessToken(ctx, firstClient, firstToken.AccessToken)
	if err != nil {
		return err
	}
	if credentials.rotate {
		password, totpSecret, err = rotateCredentials(ctx, authenticatedAccount{
			client:      firstClient,
			accessToken: accessToken,
			email:       credentials.email,
			prompt:      prompt,
		})
		if err != nil {
			return err
		}
	} else {
		info, infoErr := getMFAInfo(ctx, firstClient, accessToken)
		if infoErr != nil {
			return infoErr
		}
		if info.isEnabled() {
			if totpSecret == "" {
				totpSecret, err = prompt.askRequired("Existing TOTP secret: ")
				if err != nil {
					return err
				}
			}
		} else {
			totpSecret, err = enrollTOTP(ctx, firstClient, accessToken)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(prompt.output, "Generated TOTP secret: %s\n", totpSecret); err != nil {
				return fmt.Errorf("print TOTP secret: %w", err)
			}
		}
	}

	return finalizeCodexAuthentication(firstToken, credentials.rotate, postAccountSetupOperations{
		authenticateFinal: func() (tokenResult, error) {
			finalClient, clientErr := client.New(prompt.proxy)
			if clientErr != nil {
				return tokenResult{}, fmt.Errorf("create final OAuth client: %w", clientErr)
			}
			finalToken, _, _, authErr := authenticate(ctx, finalClient, credentials.email, password, totpSecret, prompt)
			return finalToken, authErr
		},
		save: func(token tokenResult) error {
			if token.Email == "" {
				token.Email = credentials.email
			}
			path, saveErr := saveCredential(prompt.outputDirectory, token)
			if saveErr != nil {
				return saveErr
			}
			_, outputErr := fmt.Fprintf(prompt.output, "CPA credential saved: %s\n", path)
			return outputErr
		},
	})
}

func authenticate(ctx context.Context, c *client.Client, email, password, totpSecret string, prompt *prompter) (tokenResult, string, string, error) {
	session, err := initializeOAuthSession(c)
	if err != nil {
		return tokenResult{}, password, totpSecret, err
	}
	response, err := submitEmail(ctx, c, session.deviceID, email)
	if err != nil {
		return tokenResult{}, password, totpSecret, err
	}
	for step := 0; step < 20; step++ {
		state := authState(response)
		if isOAuthCompletionState(state) {
			token, completeErr := completeOAuth(ctx, c, session)
			return token, password, totpSecret, completeErr
		}
		switch state {
		case "login_password":
			if password == "" {
				password, err = prompt.askRequired("Password: ")
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			response, err = verifyPassword(ctx, c, session.deviceID, password)
		case "create_account_password", "username_password_create":
			if password == "" {
				password, err = generatePassword()
				if err == nil {
					_, err = fmt.Fprintf(prompt.output, "Generated password: %s\n", password)
				}
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			response, err = createPassword(ctx, c, session.deviceID, email, password)
			if err != nil {
				response, err = fetchAuthState(ctx, c, authBaseURL+"/create-account/password")
			}
		case "email_otp_send", "email_otp_verification":
			response, err = handleEmailVerification(ctx, c, session.deviceID, email, prompt)
		case "about_you":
			response, err = createProfile(ctx, c, session.deviceID)
		case "add_phone", "phone_channel", "phone_verification":
			response, err = handlePhoneVerification(ctx, c, prompt)
		case "mfa_challenge":
			if totpSecret == "" {
				totpSecret, err = prompt.askRequired("TOTP secret: ")
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			factorID := response.Page.Payload.FactorID
			if factorID == "" {
				return tokenResult{}, password, totpSecret, fmt.Errorf("MFA challenge has no factor ID")
			}
			response, err = verifyTOTP(ctx, c, factorID, totpSecret)
		default:
			if strings.HasPrefix(state, "error:") {
				return tokenResult{}, password, totpSecret, fmt.Errorf("OpenAI authentication state %s: %s", state, response.Error.Message)
			}
			return tokenResult{}, password, totpSecret, fmt.Errorf("unsupported OpenAI authentication state: %s", state)
		}
		if err != nil {
			return tokenResult{}, password, totpSecret, err
		}
		if isOAuthCompletionState(authState(response)) {
			response, err = fetchAuthState(ctx, c, authBaseURL+"/")
			if err != nil {
				return tokenResult{}, password, totpSecret, err
			}
			if isOAuthCompletionState(authState(response)) {
				token, completeErr := completeOAuth(ctx, c, session)
				return token, password, totpSecret, completeErr
			}
		}
	}
	return tokenResult{}, password, totpSecret, fmt.Errorf("authentication exceeded maximum state transitions")
}

func isOAuthCompletionState(state string) bool {
	return state == "ready" || state == "sign_in_with_chatgpt_codex_consent"
}

func getChatGPTAccessToken(ctx context.Context, c *client.Client, fallback string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatGPTBaseURL+"/api/auth/session", nil)
	if err != nil {
		return "", fmt.Errorf("build ChatGPT session request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", client.UA)
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("get ChatGPT session: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if fallback != "" {
			return fallback, nil
		}
		return "", fmt.Errorf("get ChatGPT session failed: status %d", resp.StatusCode)
	}
	var session struct {
		AccessToken string `json:"accessToken"`
		Alternate   string `json:"access_token"`
	}
	if err := decodeJSON(resp.Body, &session); err != nil {
		return "", err
	}
	if session.AccessToken != "" {
		return session.AccessToken, nil
	}
	if session.Alternate != "" {
		return session.Alternate, nil
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("ChatGPT session has no access token")
}
