package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"openai-tool/cpa-codex-auth/internal/client"

	"github.com/pquerna/otp/totp"
)

const chatGPTBaseURL = "https://chatgpt.com"

func verifyTOTP(ctx context.Context, c *client.Client, factorID, secret string) (authResponse, error) {
	challengeBody, err := json.Marshal(map[string]any{"id": factorID, "type": "totp", "force_fresh_challenge": false})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode MFA challenge: %w", err)
	}
	if _, err := postAuthJSON(ctx, c, "/api/accounts/mfa/issue_challenge", challengeBody, authBaseURL+"/mfa-challenge", "", ""); err != nil {
		return authResponse{}, fmt.Errorf("issue MFA challenge: %w", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return authResponse{}, fmt.Errorf("generate TOTP: %w", err)
	}
	body, err := json.Marshal(map[string]string{"code": code, "id": factorID, "type": "totp"})
	if err != nil {
		return authResponse{}, fmt.Errorf("encode MFA verification: %w", err)
	}
	return postAuthJSON(ctx, c, "/api/accounts/mfa/verify", body, authBaseURL+"/mfa-challenge", "", "")
}

type mfaInfo struct {
	Enabled         bool       `json:"mfa_enabled"`
	EnabledV2       bool       `json:"mfa_enabled_v2"`
	DefaultFactorID string     `json:"native_default_factor_id"`
	Factors         mfaFactors `json:"factors"`
}

type mfaFactors []mfaFactor

type mfaFactor struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	FactorType string `json:"factor_type"`
}

func (factors *mfaFactors) UnmarshalJSON(data []byte) error {
	var list []mfaFactor
	if err := json.Unmarshal(data, &list); err == nil {
		*factors = list
		return nil
	}

	var keyed map[string]json.RawMessage
	if err := json.Unmarshal(data, &keyed); err != nil {
		return fmt.Errorf("decode MFA factors: %w", err)
	}
	list = make([]mfaFactor, 0, len(keyed))
	for factorType, raw := range keyed {
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte{'['}) {
			var factors []mfaFactor
			if err := json.Unmarshal(raw, &factors); err != nil {
				return fmt.Errorf("decode MFA factor %q: %w", factorType, err)
			}
			for index := range factors {
				if factors[index].Type == "" {
					factors[index].Type = factorType
				}
			}
			list = append(list, factors...)
			continue
		}

		var factor mfaFactor
		if err := json.Unmarshal(raw, &factor); err != nil {
			return fmt.Errorf("decode MFA factor %q: %w", factorType, err)
		}
		if factor.Type == "" {
			factor.Type = factorType
		}
		list = append(list, factor)
	}
	*factors = list
	return nil
}

type mfaSession struct {
	client      *client.Client
	accessToken string
}

func (info mfaInfo) isEnabled() bool {
	return info.Enabled || info.EnabledV2
}

func (info mfaInfo) authenticatorFactorID() (string, error) {
	for _, factor := range info.Factors {
		if factor.ID == info.DefaultFactorID && factor.isAuthenticatorType() {
			return factor.ID, nil
		}
	}
	for _, factor := range info.Factors {
		if factor.ID != "" && factor.isAuthenticatorType() {
			return factor.ID, nil
		}
	}
	if info.DefaultFactorID != "" && len(info.Factors) == 0 {
		return info.DefaultFactorID, nil
	}
	return "", fmt.Errorf("MFA metadata has no authenticator factor")
}

func (factor mfaFactor) isAuthenticatorType() bool {
	factorType := strings.ToLower(factor.Type)
	if factorType == "" {
		factorType = strings.ToLower(factor.FactorType)
	}
	return factorType == "totp" || factorType == "authenticator" || factorType == "authenticator_app"
}

func getMFAInfo(ctx context.Context, c *client.Client, accessToken string) (mfaInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatGPTBaseURL+"/backend-api/accounts/mfa_info", nil)
	if err != nil {
		return mfaInfo{}, fmt.Errorf("build MFA info request: %w", err)
	}
	setChatGPTHeaders(c, req, accessToken)
	resp, err := c.Do(req)
	if err != nil {
		return mfaInfo{}, fmt.Errorf("get MFA info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return mfaInfo{}, fmt.Errorf("get MFA info failed: status %d", resp.StatusCode)
	}
	var info mfaInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return mfaInfo{}, fmt.Errorf("decode MFA info: %w", err)
	}
	return info, nil
}

func enrollTOTP(ctx context.Context, c *client.Client, accessToken string) (string, error) {
	body := strings.NewReader(`{"factor_type":"totp"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatGPTBaseURL+"/backend-api/accounts/mfa/enroll", body)
	if err != nil {
		return "", fmt.Errorf("build TOTP enrollment: %w", err)
	}
	setChatGPTHeaders(c, req, accessToken)
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("enroll TOTP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("enroll TOTP failed: status %d", resp.StatusCode)
	}
	var enrollment struct {
		Secret    string `json:"secret"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollment); err != nil {
		return "", fmt.Errorf("decode TOTP enrollment: %w", err)
	}
	if enrollment.Secret == "" || enrollment.SessionID == "" {
		return "", fmt.Errorf("TOTP enrollment response is incomplete")
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("generate enrollment TOTP: %w", err)
	}
	activation, err := json.Marshal(map[string]string{"session_id": enrollment.SessionID, "code": code, "factor_type": "totp"})
	if err != nil {
		return "", fmt.Errorf("encode TOTP activation: %w", err)
	}
	activateReq, err := http.NewRequestWithContext(ctx, http.MethodPost, chatGPTBaseURL+"/backend-api/accounts/mfa/user/activate_enrollment", strings.NewReader(string(activation)))
	if err != nil {
		return "", fmt.Errorf("build TOTP activation: %w", err)
	}
	setChatGPTHeaders(c, activateReq, accessToken)
	activateResp, err := c.Do(activateReq)
	if err != nil {
		return "", fmt.Errorf("activate TOTP: %w", err)
	}
	defer activateResp.Body.Close()
	if activateResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("activate TOTP failed: status %d", activateResp.StatusCode)
	}
	return enrollment.Secret, nil
}

func disableTOTP(ctx context.Context, session mfaSession, factorID string) error {
	body, err := json.Marshal(map[string]string{"factor_id": factorID})
	if err != nil {
		return fmt.Errorf("encode TOTP disable request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, chatGPTBaseURL+"/backend-api/accounts/mfa/user/disable_in_house", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build TOTP disable request: %w", err)
	}
	setChatGPTHeaders(session.client, req, session.accessToken)
	resp, err := session.client.Do(req)
	if err != nil {
		return fmt.Errorf("disable TOTP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("disable TOTP failed: status %d", resp.StatusCode)
	}
	return nil
}

func setChatGPTHeaders(c *client.Client, req *http.Request, accessToken string) {
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", client.UA)
	req.Header.Set("Origin", chatGPTBaseURL)
	req.Header.Set("Referer", chatGPTBaseURL+"/")
	req.Header.Set("Oai-Device-Id", c.GetCookieValue("oai-did"))
	req.Header.Set("Oai-Session-Id", c.GetCookieValue("oai-session-id"))
}
