package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var errUnexpectedFinalAuthentication = errors.New("second authentication must not be called")

func TestOAuthCompletionState_whenCodexConsentIsRequired_returnsTrue(t *testing.T) {
	// Given: authentication reached the Codex consent page.
	state := "sign_in_with_chatgpt_codex_consent"

	// When: the state is classified for the authentication loop.
	ready := isOAuthCompletionState(state)

	// Then: workspace selection and OAuth completion should run.
	if !ready {
		t.Fatal("Codex consent state was not classified as OAuth completion")
	}
}

func TestFinalizeCodexAuthentication_whenNotRotating_savesFirstTokenWithoutSecondAuthentication(t *testing.T) {
	// Given: the first authentication returns a complete Codex token.
	firstToken := tokenResult{
		AccessToken:  "first-access-token",
		RefreshToken: "first-refresh-token",
		Email:        "user@example.com",
	}
	var savedToken tokenResult
	secondAuthenticationCalls := 0
	operations := postAccountSetupOperations{
		authenticateFinal: func() (tokenResult, error) {
			secondAuthenticationCalls++
			return tokenResult{}, errUnexpectedFinalAuthentication
		},
		save: func(token tokenResult) error {
			savedToken = token
			return nil
		},
	}

	// When: the authentication orchestration runs to credential saving.
	err := finalizeCodexAuthentication(firstToken, 0, operations)

	// Then: the first token reaches saving and final OAuth authentication is not called.
	if err != nil {
		t.Fatalf("finalizeCodexAuthentication returned error: %v", err)
	}
	if savedToken.AccessToken != firstToken.AccessToken {
		t.Fatalf("saved access token = %q, want %q", savedToken.AccessToken, firstToken.AccessToken)
	}
	if secondAuthenticationCalls != 0 {
		t.Fatalf("final authentication calls = %d, want 0", secondAuthenticationCalls)
	}
}

func TestFinalizeCodexAuthentication_whenLoginOnly_doesNotCreateChangeLog(t *testing.T) {
	// Given: a successful login that only needs its CPA credential saved.
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	outputDirectory := filepath.Join(workingDirectory, "output")
	token := tokenResult{Email: "user@example.com"}
	operations := postAccountSetupOperations{
		authenticateFinal: func() (tokenResult, error) {
			return tokenResult{}, errUnexpectedFinalAuthentication
		},
		save: func(token tokenResult) error {
			_, err := saveCredential(outputDirectory, token)
			return err
		},
	}

	// When: login finalization saves the CPA credential.
	err := finalizeCodexAuthentication(token, 0, operations)

	// Then: no account-change audit log is created.
	if err != nil {
		t.Fatalf("finalize login-only authentication: %v", err)
	}
	if _, err := os.Stat("cpa-codex-auth.credentials"); !os.IsNotExist(err) {
		t.Fatalf("credential change log exists or stat failed: %v", err)
	}
}

func TestFinalizeCodexAuthentication_whenRotating_savesFinalTokenAfterOneAuthentication(t *testing.T) {
	// Given: rotation requires a fresh OAuth token after credentials change.
	firstToken := tokenResult{AccessToken: "first-access-token"}
	finalToken := tokenResult{AccessToken: "final-access-token"}
	authenticationCalls := 0
	var savedToken tokenResult
	operations := postAccountSetupOperations{
		authenticateFinal: func() (tokenResult, error) {
			authenticationCalls++
			return finalToken, nil
		},
		save: func(token tokenResult) error {
			savedToken = token
			return nil
		},
	}

	// When: the authentication finalization runs in rotate mode.
	err := finalizeCodexAuthentication(firstToken, rotateTOTP, operations)

	// Then: final authentication runs once and its token is saved.
	if err != nil {
		t.Fatalf("finalizeCodexAuthentication returned error: %v", err)
	}
	if authenticationCalls != 1 {
		t.Fatalf("final authentication calls = %d, want 1", authenticationCalls)
	}
	if savedToken.AccessToken != finalToken.AccessToken {
		t.Fatalf("saved access token = %q, want %q", savedToken.AccessToken, finalToken.AccessToken)
	}
}
