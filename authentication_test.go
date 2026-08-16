package main

import (
	"bytes"
	"context"
	"testing"
)

func TestAuthenticateSession_whenPasswordIsCreated_appendsPasswordChange(t *testing.T) {
	// Given: authentication reaches the account-password creation state.
	var createResponse authResponse
	createResponse.Page.Type = "create_account_password"
	var readyResponse authResponse
	readyResponse.Page.Type = "ready"
	changes := make([]credentialChange, 0, 1)
	prompt := &prompter{output: &bytes.Buffer{}}
	operations := authenticationOperations{
		submitEmail: func(context.Context, authenticationEmailRequest) (authResponse, error) {
			return createResponse, nil
		},
		createPassword: func(context.Context, authenticationPasswordRequest) (authResponse, error) {
			return readyResponse, nil
		},
		fetchAuthState: func(context.Context, *oauthSession, string) (authResponse, error) {
			return readyResponse, nil
		},
		completeOAuth: func(context.Context, *oauthSession) (tokenResult, error) {
			return tokenResult{Email: "user@example.com"}, nil
		},
	}

	// When: the account password is created successfully.
	_, password, _, err := authenticateSession(context.Background(), authenticationRequest{
		Session: &oauthSession{},
		Email:   "user@example.com",
		Prompt:  prompt,
		appendChange: func(change credentialChange) error {
			changes = append(changes, change)
			return nil
		},
	}, operations)

	// Then: exactly the created password is recorded as a password change.
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	if password == "" || len(changes) != 1 || changes[0].Operation != credentialChangePasswordSet || changes[0].Password != password {
		t.Fatalf("password = %q, changes = %#v", password, changes)
	}
}
