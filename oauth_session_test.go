package main

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"openai-tool/cpa-codex-auth/internal/client"
)

func TestEstablishOAuthSession_whenHTTPInitializationIsForbidden(t *testing.T) {
	// Given: HTTP initialization is forbidden and browser fallback can establish the session.
	browserCalls := 0
	wantErr := errors.New("browser fallback failed")
	ops := oauthSessionOperations{
		initializeHTTP: func() (oauthInitializationResult, error) {
			return oauthInitializationResult{statusCode: http.StatusForbidden}, nil
		},
		hasAuthSession: func() bool { return false },
		fallbackBrowser: func() error {
			browserCalls++
			return wantErr
		},
	}

	// When: OAuth session initialization runs.
	err := establishOAuthSession(ops)

	// Then: the browser fallback runs once and its error is returned.
	if browserCalls != 1 {
		t.Fatalf("browser calls = %d, want 1", browserCalls)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestEstablishOAuthSession_whenHTTPCompletesWithoutAuthSession(t *testing.T) {
	// Given: HTTP initialization completes but does not establish the auth session.
	browserCalls := 0
	wantErr := errors.New("browser fallback failed")
	ops := oauthSessionOperations{
		initializeHTTP: func() (oauthInitializationResult, error) {
			return oauthInitializationResult{statusCode: http.StatusOK}, nil
		},
		hasAuthSession: func() bool { return false },
		fallbackBrowser: func() error {
			browserCalls++
			return wantErr
		},
	}

	// When: OAuth session initialization runs.
	err := establishOAuthSession(ops)

	// Then: the browser fallback runs once and its error is returned.
	if browserCalls != 1 {
		t.Fatalf("browser calls = %d, want 1", browserCalls)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestEstablishOAuthSession_whenHTTPCompletesWithAuthSession(t *testing.T) {
	// Given: HTTP initialization completes and establishes the auth session.
	browserCalls := 0
	ops := oauthSessionOperations{
		initializeHTTP: func() (oauthInitializationResult, error) {
			return oauthInitializationResult{statusCode: http.StatusOK}, nil
		},
		hasAuthSession: func() bool { return true },
		fallbackBrowser: func() error {
			browserCalls++
			return errors.New("browser fallback should not run")
		},
	}

	// When: OAuth session initialization runs.
	err := establishOAuthSession(ops)

	// Then: initialization succeeds without invoking browser fallback.
	if browserCalls != 0 {
		t.Fatalf("browser calls = %d, want 0", browserCalls)
	}
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
}

func TestEnsureDeviceID_whenCookieIsMissing(t *testing.T) {
	// Given: a new client with no OAuth device cookie.
	c, err := client.New("")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When: OAuth initialization requests a device ID.
	deviceID := ensureDeviceID(c)

	// Then: a valid UUID is persisted as the oai-did cookie.
	if _, err := uuid.Parse(deviceID); err != nil {
		t.Fatalf("device ID is not a UUID: %q", deviceID)
	}
	if got := c.GetCookieValue("oai-did"); got != deviceID {
		t.Fatalf("stored device ID = %q, want %q", got, deviceID)
	}
}

func TestEnsureDeviceID_whenCookieAlreadyExists(t *testing.T) {
	// Given: a client with a server-provided device cookie.
	c, err := client.New("")
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	const existing = "b83ad52a-9c6d-49bd-a6ae-35c4202781cd"
	c.SetCookie(authBaseURL, "oai-did", existing)

	// When: OAuth initialization requests a device ID.
	deviceID := ensureDeviceID(c)

	// Then: the existing identity is preserved.
	if deviceID != existing {
		t.Fatalf("device ID = %q, want existing %q", deviceID, existing)
	}
}
