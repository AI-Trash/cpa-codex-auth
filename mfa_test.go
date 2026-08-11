package main

import "testing"

func TestAuthenticatorFactorID_whenModernMFAInfoContainsTOTP(t *testing.T) {
	// Given: modern MFA metadata with both a default authenticator and another factor.
	info := mfaInfo{
		EnabledV2:       true,
		DefaultFactorID: "totp-factor",
		Factors: []mfaFactor{
			{ID: "sms-factor", Type: "sms"},
			{ID: "totp-factor", Type: "totp"},
		},
	}

	// When: the factor to disable is selected.
	factorID, err := info.authenticatorFactorID()

	// Then: the authenticator factor is returned, never the SMS factor.
	if err != nil {
		t.Fatalf("authenticatorFactorID returned error: %v", err)
	}
	if factorID != "totp-factor" {
		t.Fatalf("authenticatorFactorID = %q, want %q", factorID, "totp-factor")
	}
}
