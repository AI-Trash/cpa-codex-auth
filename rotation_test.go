package main

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"openai-tool/cpa-codex-auth/internal/client"
)

func TestExecuteCredentialRotation_enrollsTOTP_beforePasswordReset(t *testing.T) {
	// Given: enabled MFA and rotation operations that record their call order.
	var calls []string
	request := credentialRotationRequest{
		account: authenticatedAccount{prompt: &prompter{output: new(bytes.Buffer)}},
		info: mfaInfo{
			EnabledV2:       true,
			DefaultFactorID: "old-totp",
			Factors:         []mfaFactor{{ID: "old-totp", Type: "totp"}},
		},
		newPassword: "new-password",
	}
	operations := credentialRotationOperations{
		disableTOTP: func(context.Context, mfaSession, string) error {
			calls = append(calls, "disable")
			return nil
		},
		enrollTOTP: func(context.Context, *client.Client, string) (string, error) {
			calls = append(calls, "enroll")
			return "new-totp", nil
		},
		resetPassword: func(context.Context, passwordReset) error {
			calls = append(calls, "reset")
			return nil
		},
	}

	// When: credentials are rotated.
	_, err := executeCredentialRotation(context.Background(), request, operations)

	// Then: the replacement authenticator is active before password reset starts.
	if err != nil {
		t.Fatalf("executeCredentialRotation returned error: %v", err)
	}
	want := []string{"disable", "enroll", "reset"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rotation calls = %v, want %v", calls, want)
	}
}
