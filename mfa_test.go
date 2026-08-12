package main

import (
	"encoding/json"
	"testing"
)

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

func TestMFAInfoDecode_whenFactorsIsObject(t *testing.T) {
	// Given: the current API shape where factors is keyed by factor type.
	payload := []byte(`{
		"mfa_enabled": true,
		"native_default_factor_id": "totp-factor",
		"factors": {
			"sms": {"id": "sms-factor"},
			"totp": {"id": "totp-factor"}
		}
	}`)

	// When: MFA metadata is decoded at the API boundary.
	var info mfaInfo
	err := json.Unmarshal(payload, &info)

	// Then: the keyed TOTP factor is normalized and selectable.
	if err != nil {
		t.Fatalf("decode MFA info: %v", err)
	}
	factorID, err := info.authenticatorFactorID()
	if err != nil {
		t.Fatalf("authenticatorFactorID returned error: %v", err)
	}
	if factorID != "totp-factor" {
		t.Fatalf("authenticatorFactorID = %q, want %q", factorID, "totp-factor")
	}
}

func TestMFAInfoDecode_whenKeyedFactorsContainArrays(t *testing.T) {
	// Given: MFA metadata where each keyed factor type contains a list of factors.
	payload := []byte(`{
		"mfa_enabled": true,
		"native_default_factor_id": "totp-factor",
		"factors": {
			"totp": [{"id": "totp-factor"}]
		}
	}`)

	// When: MFA metadata is decoded at the API boundary.
	var info mfaInfo
	err := json.Unmarshal(payload, &info)

	// Then: the keyed factor arrays are normalized and the TOTP factor is selectable.
	if err != nil {
		t.Fatalf("decode MFA info with keyed factor arrays: %v", err)
	}
	factorID, err := info.authenticatorFactorID()
	if err != nil {
		t.Fatalf("authenticatorFactorID returned error: %v", err)
	}
	if factorID != "totp-factor" {
		t.Fatalf("authenticatorFactorID = %q, want %q", factorID, "totp-factor")
	}
}
