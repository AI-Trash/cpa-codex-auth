package main

import (
	"testing"

	"github.com/google/uuid"

	"openai-tool/cpa-codex-auth/internal/client"
)

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
