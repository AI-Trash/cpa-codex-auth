package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
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
		refreshSession: func(context.Context, string, string) (*authenticatedOAuth, error) {
			calls = append(calls, "refresh")
			return &authenticatedOAuth{session: &oauthSession{client: &client.Client{}}}, nil
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
	want := []string{"disable", "enroll", "refresh", "reset"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rotation calls = %v, want %v", calls, want)
	}
}

func TestExecuteCredentialRotation_whenBothSelected_resetsWithRefreshedClient(t *testing.T) {
	// Given: TOTP enrollment invalidates the original authenticated session.
	var calls []string
	var refreshedClient *client.Client
	request := credentialRotationRequest{
		account: authenticatedAccount{
			client: &client.Client{},
			prompt: &prompter{output: new(bytes.Buffer)},
		},
		info: mfaInfo{
			EnabledV2:       true,
			DefaultFactorID: "old-totp",
			Factors:         []mfaFactor{{ID: "old-totp", Type: "totp"}},
		},
		currentPassword: "current-password",
		newPassword:     "new-password",
	}
	operations := credentialRotationOperations{
		disableTOTP: func(context.Context, mfaSession, string) error {
			calls = append(calls, "disable")
			return nil
		},
		enrollTOTP: func(_ context.Context, c *client.Client, _ string) (string, error) {
			calls = append(calls, "enroll")
			return "new-totp", nil
		},
		refreshSession: func(_ context.Context, password, totpSecret string) (*authenticatedOAuth, error) {
			calls = append(calls, "refresh")
			if password != "current-password" || totpSecret != "new-totp" {
				t.Fatalf("refresh inputs = (%q, %q), want (%q, %q)", password, totpSecret, "current-password", "new-totp")
			}
			refreshedClient = &client.Client{}
			return &authenticatedOAuth{session: &oauthSession{client: refreshedClient}}, nil
		},
		resetPassword: func(_ context.Context, reset passwordReset) error {
			calls = append(calls, "reset")
			if reset.client != refreshedClient {
				t.Fatalf("password reset client = %p, want refreshed client %p", reset.client, refreshedClient)
			}
			return nil
		},
	}

	// When: both credentials are rotated.
	_, _, err := executeCredentialRotation(context.Background(), request, rotateTOTP|rotatePassword, operations)

	// Then: reset runs after reauthentication and receives that exact refreshed client.
	if err != nil {
		t.Fatalf("executeCredentialRotation returned error: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"disable", "enroll", "refresh", "reset"}) {
		t.Fatalf("rotation calls = %v, want [disable enroll refresh reset]", calls)
	}
}

func TestExecuteCredentialRotation_closesRefreshedBrowser_whenPasswordResetFails(t *testing.T) {
	// Given: a combined rotation whose refreshed authentication owns an active browser.
	browser := &closeTrackingOAuthBrowser{}
	refreshed := &authenticatedOAuth{session: &oauthSession{
		client:  &client.Client{},
		browser: browser,
	}}
	request := credentialRotationRequest{
		account:     authenticatedAccount{prompt: &prompter{output: new(bytes.Buffer)}},
		newPassword: "new-password",
	}
	resetErr := errors.New("password reset failed")
	operations := credentialRotationOperations{
		enrollTOTP: func(context.Context, *client.Client, string) (string, error) {
			return "new-totp", nil
		},
		refreshSession: func(context.Context, string, string) (*authenticatedOAuth, error) {
			return refreshed, nil
		},
		resetPassword: func(_ context.Context, reset passwordReset) error {
			if reset.client != refreshed.session.client {
				t.Fatalf("password reset client = %p, want refreshed client %p", reset.client, refreshed.session.client)
			}
			if browser.closeCalls != 0 {
				t.Fatalf("browser close calls during password reset = %d, want 0", browser.closeCalls)
			}
			return resetErr
		},
	}

	// When: the refreshed session performs the password reset.
	_, _, err := executeCredentialRotation(context.Background(), request, rotateTOTP|rotatePassword, operations)

	// Then: its browser stays attached through the reset and closes exactly afterward.
	if !errors.Is(err, resetErr) {
		t.Fatalf("executeCredentialRotation error = %v, want %v", err, resetErr)
	}
	if browser.closeCalls != 1 {
		t.Fatalf("browser close calls after password reset = %d, want 1", browser.closeCalls)
	}
}

type closeTrackingOAuthBrowser struct {
	closeCalls int
}

func (*closeTrackingOAuthBrowser) Fetch(context.Context, oauthBrowserFetchRequest) (*http.Response, error) {
	return nil, nil
}

func (*closeTrackingOAuthBrowser) FollowRedirects(context.Context, oauthBrowserRedirectRequest) (string, error) {
	return "", nil
}

func (b *closeTrackingOAuthBrowser) Close() {
	b.closeCalls++
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

func TestExecuteCredentialRotation_appendsEachSuccessfulAccountChange(t *testing.T) {
	// Given: a combined rotation with an existing authenticator.
	var changes []credentialChange
	request := credentialRotationRequest{
		account:     authenticatedAccount{client: &client.Client{}, email: "user@example.com", prompt: &prompter{output: new(bytes.Buffer)}},
		info:        mfaInfo{EnabledV2: true, DefaultFactorID: "old-totp", Factors: []mfaFactor{{ID: "old-totp", Type: "totp"}}},
		newPassword: "new-password",
	}
	operations := credentialRotationOperations{
		disableTOTP: func(context.Context, mfaSession, string) error { return nil },
		enrollTOTP:  func(context.Context, *client.Client, string) (string, error) { return "new-totp", nil },
		refreshSession: func(context.Context, string, string) (*authenticatedOAuth, error) {
			return &authenticatedOAuth{session: &oauthSession{client: &client.Client{}}}, nil
		},
		resetPassword: func(context.Context, passwordReset) error { return nil },
		appendChange: func(change credentialChange) error {
			changes = append(changes, change)
			return nil
		},
	}

	// When: all selected mutations succeed.
	_, _, err := executeCredentialRotation(context.Background(), request, rotateTOTP|rotatePassword, operations)

	// Then: disable, enrollment, and password reset each produce one detailed append record.
	if err != nil {
		t.Fatalf("execute credential rotation: %v", err)
	}
	wantOperations := []string{credentialChangeTOTPDisabled, credentialChangeTOTPEnrolled, credentialChangePasswordReset}
	if len(changes) != len(wantOperations) {
		t.Fatalf("credential changes = %#v", changes)
	}
	for index, operation := range wantOperations {
		if changes[index].Operation != operation || changes[index].Email != request.account.email {
			t.Fatalf("credential change %d = %#v", index, changes[index])
		}
	}
	if changes[0].FactorID != "old-totp" || changes[1].TOTPSecret != "new-totp" || changes[2].Password != "new-password" {
		t.Fatalf("credential change details = %#v", changes)
	}
}
