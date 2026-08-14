package main

import (
	"context"
	"fmt"
	"strings"
)

type authenticationRequest struct {
	Session    *oauthSession
	Email      string
	Password   string
	TOTPSecret string
	Prompt     *prompter
}

type authenticationEmailRequest struct {
	Session *oauthSession
	Email   string
	Prompt  *prompter
}

type authenticationPasswordRequest struct {
	Session  *oauthSession
	Email    string
	Password string
}

type authenticationPhoneRequest struct {
	Session *oauthSession
	Prompt  *prompter
}

type authenticationMFARequest struct {
	Session    *oauthSession
	FactorID   string
	TOTPSecret string
}

type authenticationOperations struct {
	submitEmail             func(context.Context, authenticationEmailRequest) (authResponse, error)
	verifyPassword          func(context.Context, authenticationPasswordRequest) (authResponse, error)
	createPassword          func(context.Context, authenticationPasswordRequest) (authResponse, error)
	handleEmailVerification func(context.Context, authenticationEmailRequest) (authResponse, error)
	createProfile           func(context.Context, *oauthSession) (authResponse, error)
	handlePhoneVerification func(context.Context, authenticationPhoneRequest) (authResponse, error)
	verifyTOTP              func(context.Context, authenticationMFARequest) (authResponse, error)
	fetchAuthState          func(context.Context, *oauthSession, string) (authResponse, error)
	completeOAuth           func(context.Context, *oauthSession) (tokenResult, error)
}

func defaultAuthenticationOperations() authenticationOperations {
	return authenticationOperations{
		submitEmail: func(ctx context.Context, request authenticationEmailRequest) (authResponse, error) {
			return submitEmail(ctx, request.Session.client, request.Session.deviceID, request.Email)
		},
		verifyPassword: func(ctx context.Context, request authenticationPasswordRequest) (authResponse, error) {
			return verifyPassword(ctx, request.Session.client, request.Session.deviceID, request.Password)
		},
		createPassword: func(ctx context.Context, request authenticationPasswordRequest) (authResponse, error) {
			return createPassword(ctx, request.Session.client, request.Session.deviceID, request.Email, request.Password)
		},
		handleEmailVerification: func(ctx context.Context, request authenticationEmailRequest) (authResponse, error) {
			return handleEmailVerification(ctx, request.Session.client, request.Session.deviceID, request.Email, request.Prompt)
		},
		createProfile: func(ctx context.Context, session *oauthSession) (authResponse, error) {
			return createProfile(ctx, session.client, session.deviceID)
		},
		handlePhoneVerification: func(ctx context.Context, request authenticationPhoneRequest) (authResponse, error) {
			return handlePhoneVerification(ctx, request.Session.client, request.Prompt)
		},
		verifyTOTP: func(ctx context.Context, request authenticationMFARequest) (authResponse, error) {
			return verifyTOTP(ctx, request.Session.client, request.FactorID, request.TOTPSecret)
		},
		fetchAuthState: func(ctx context.Context, session *oauthSession, referer string) (authResponse, error) {
			return fetchAuthState(ctx, session.client, referer)
		},
		completeOAuth: completeOAuth,
	}
}

func authenticateSession(ctx context.Context, request authenticationRequest, operations authenticationOperations) (tokenResult, string, string, error) {
	password := request.Password
	totpSecret := request.TOTPSecret
	response, err := operations.submitEmail(ctx, authenticationEmailRequest{Session: request.Session, Email: request.Email, Prompt: request.Prompt})
	if err != nil {
		return tokenResult{}, password, totpSecret, err
	}
	for step := 0; step < 20; step++ {
		state := authState(response)
		if isOAuthCompletionState(state) {
			token, completeErr := operations.completeOAuth(ctx, request.Session)
			return token, password, totpSecret, completeErr
		}
		switch state {
		case "login_password":
			if password == "" {
				password, err = request.Prompt.askRequired("Password: ")
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			response, err = operations.verifyPassword(ctx, authenticationPasswordRequest{Session: request.Session, Password: password})
		case "create_account_password", "username_password_create":
			if password == "" {
				password, err = generatePassword()
				if err == nil {
					_, err = fmt.Fprintf(request.Prompt.output, "Generated password: %s\n", password)
				}
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			response, err = operations.createPassword(ctx, authenticationPasswordRequest{Session: request.Session, Email: request.Email, Password: password})
			if err != nil {
				response, err = operations.fetchAuthState(ctx, request.Session, authBaseURL+"/create-account/password")
			}
		case "email_otp_send", "email_otp_verification":
			response, err = operations.handleEmailVerification(ctx, authenticationEmailRequest{Session: request.Session, Email: request.Email, Prompt: request.Prompt})
		case "about_you":
			response, err = operations.createProfile(ctx, request.Session)
		case "add_phone", "phone_channel", "phone_verification":
			response, err = operations.handlePhoneVerification(ctx, authenticationPhoneRequest{Session: request.Session, Prompt: request.Prompt})
		case "mfa_challenge":
			if totpSecret == "" {
				totpSecret, err = request.Prompt.askRequired("TOTP secret: ")
				if err != nil {
					return tokenResult{}, password, totpSecret, err
				}
			}
			factorID := response.Page.Payload.FactorID
			if factorID == "" {
				return tokenResult{}, password, totpSecret, fmt.Errorf("MFA challenge has no factor ID")
			}
			response, err = operations.verifyTOTP(ctx, authenticationMFARequest{Session: request.Session, FactorID: factorID, TOTPSecret: totpSecret})
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
			response, err = operations.fetchAuthState(ctx, request.Session, authBaseURL+"/")
			if err != nil {
				return tokenResult{}, password, totpSecret, err
			}
			if isOAuthCompletionState(authState(response)) {
				token, completeErr := operations.completeOAuth(ctx, request.Session)
				return token, password, totpSecret, completeErr
			}
		}
	}
	return tokenResult{}, password, totpSecret, fmt.Errorf("authentication exceeded maximum state transitions")
}
