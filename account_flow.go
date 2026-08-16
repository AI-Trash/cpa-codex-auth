package main

import (
	"context"
	"fmt"
	"net/http"

	"openai-tool/cpa-codex-auth/internal/client"
)

type postAccountSetupOperations struct {
	authenticateFinal func() (tokenResult, error)
	save              func(tokenResult) error
}

type authenticatedOAuth struct {
	session    *oauthSession
	token      tokenResult
	password   string
	totpSecret string
}

func (result *authenticatedOAuth) Close() {
	result.session.Close()
}

func finalizeCodexAuthentication(firstToken tokenResult, rotate rotationTargets, operations postAccountSetupOperations) error {
	token := firstToken
	if rotate != 0 {
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
	firstAuthentication, err := authenticate(ctx, firstClient, credentials.email, password, totpSecret, credentials.credentialLogEnabled, prompt)
	if err != nil {
		return err
	}
	firstAuthenticationOpen := true
	defer func() {
		if firstAuthenticationOpen {
			firstAuthentication.Close()
		}
	}()
	firstToken := firstAuthentication.token
	password = firstAuthentication.password
	totpSecret = firstAuthentication.totpSecret
	accessToken, err := getChatGPTAccessToken(ctx, firstClient, firstToken.AccessToken)
	if err != nil {
		return err
	}
	if credentials.rotate != 0 {
		password, totpSecret, err = rotateCredentials(ctx, authenticatedAccount{
			client:               firstClient,
			accessToken:          accessToken,
			email:                credentials.email,
			credentialLogEnabled: credentials.credentialLogEnabled,
			prompt:               prompt,
		}, credentials.rotate, password, totpSecret)
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
			if err := appendCredentialChange(credentialChange{Email: credentials.email, Operation: credentialChangeTOTPEnrolled, TOTPSecret: totpSecret}, credentials.credentialLogEnabled); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(prompt.output, "Generated TOTP secret: %s\n", totpSecret); err != nil {
				return fmt.Errorf("print TOTP secret: %w", err)
			}
		}
	}
	firstAuthentication.Close()
	firstAuthenticationOpen = false

	return finalizeCodexAuthentication(firstToken, credentials.rotate, postAccountSetupOperations{
		authenticateFinal: func() (tokenResult, error) {
			finalClient, clientErr := client.New(prompt.proxy)
			if clientErr != nil {
				return tokenResult{}, fmt.Errorf("create final OAuth client: %w", clientErr)
			}
			finalAuthentication, authErr := authenticate(ctx, finalClient, credentials.email, password, totpSecret, credentials.credentialLogEnabled, prompt)
			if authErr != nil {
				return tokenResult{}, authErr
			}
			defer finalAuthentication.Close()
			return finalAuthentication.token, nil
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
			if outputErr != nil {
				return outputErr
			}
			return nil
		},
	})
}

func authenticate(ctx context.Context, c *client.Client, email, password, totpSecret string, credentialLogEnabled bool, prompt *prompter) (*authenticatedOAuth, error) {
	session, err := initializeOAuthSession(ctx, c)
	if err != nil {
		return nil, err
	}
	token, authenticatedPassword, authenticatedTOTPSecret, err := authenticateSession(ctx, authenticationRequest{
		Session:    session,
		Email:      email,
		Password:   password,
		TOTPSecret: totpSecret,
		Prompt:     prompt,
		appendChange: func(change credentialChange) error {
			return appendCredentialChange(change, credentialLogEnabled)
		},
	}, defaultAuthenticationOperations())
	if err != nil {
		session.Close()
		return nil, err
	}
	return &authenticatedOAuth{
		session:    session,
		token:      token,
		password:   authenticatedPassword,
		totpSecret: authenticatedTOTPSecret,
	}, nil
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
