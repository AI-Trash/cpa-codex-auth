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
	_, _, err := executeCredentialRotation(context.Background(), request, rotateTOTP|rotatePassword, operations)

	// Then: the replacement authenticator is active before password reset starts.
	if err != nil {
		t.Fatalf("executeCredentialRotation returned error: %v", err)
	}
	want := []string{"disable", "enroll", "reset"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rotation calls = %v, want %v", calls, want)
	}
}

func TestExecuteCredentialRotation_whenPasswordOnly_preservesTOTPAndSkipsMFA(t *testing.T) {
	// Given: password-only rotation operations.
	calls := []string{}
	request := credentialRotationRequest{account: authenticatedAccount{prompt: &prompter{output: new(bytes.Buffer)}}, newPassword: "new-password"}
	operations := credentialRotationOperations{
		disableTOTP: func(context.Context, mfaSession, string) error { calls = append(calls, "disable"); return nil },
		enrollTOTP: func(context.Context, *client.Client, string) (string, error) {
			calls = append(calls, "enroll")
			return "new-totp", nil
		},
		resetPassword: func(context.Context, passwordReset) error { calls = append(calls, "reset"); return nil },
	}

	// When: only the password target is rotated.
	newTOTP, newPassword, err := executeCredentialRotation(context.Background(), request, rotatePassword, operations)

	// Then: only password changes and no TOTP value is produced.
	if err != nil {
		t.Fatalf("executeCredentialRotation returned error: %v", err)
	}
	if newTOTP != "" || newPassword != "new-password" {
		t.Fatalf("rotated credentials = %q, %q", newTOTP, newPassword)
	}
	if !reflect.DeepEqual(calls, []string{"reset"}) {
		t.Fatalf("rotation calls = %v, want [reset]", calls)
	}
}

func TestExecuteCredentialRotation_whenTOTPOnly_preservesPasswordAndSkipsReset(t *testing.T) {
	// Given: TOTP-only rotation operations.
	calls := []string{}
	request := credentialRotationRequest{account: authenticatedAccount{prompt: &prompter{output: new(bytes.Buffer)}}}
	operations := credentialRotationOperations{
		disableTOTP: func(context.Context, mfaSession, string) error { calls = append(calls, "disable"); return nil },
		enrollTOTP: func(context.Context, *client.Client, string) (string, error) {
			calls = append(calls, "enroll")
			return "new-totp", nil
		},
		resetPassword: func(context.Context, passwordReset) error { calls = append(calls, "reset"); return nil },
	}

	// When: only the TOTP target is rotated.
	newTOTP, newPassword, err := executeCredentialRotation(context.Background(), request, rotateTOTP, operations)

	// Then: only TOTP changes and the password remains absent.
	if err != nil {
		t.Fatalf("executeCredentialRotation returned error: %v", err)
	}
	if newTOTP != "new-totp" || newPassword != "" {
		t.Fatalf("rotated credentials = %q, %q", newTOTP, newPassword)
	}
	if !reflect.DeepEqual(calls, []string{"enroll"}) {
		t.Fatalf("rotation calls = %v, want [enroll]", calls)
	}
}
