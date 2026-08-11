package main

import "testing"

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
