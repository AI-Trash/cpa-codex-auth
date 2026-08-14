package openai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"openai-tool/cpa-codex-auth/internal/client"
)

type SentinelChallenge struct {
	Token       string `json:"token"`
	ProofOfWork struct {
		Required   bool   `json:"required"`
		Seed       string `json:"seed"`
		Difficulty string `json:"difficulty"`
	} `json:"proofofwork"`
}

func BuildFullSentinelToken(c *client.Client, deviceID, flow string) (string, string, error) {
	generator := NewSentinelGenerator(deviceID)
	requirements := generator.GenerateRequirementsToken()
	body := fmt.Sprintf(`{"p":"%s","id":"%s","flow":"%s"}`, requirements, deviceID, flow)
	req, err := http.NewRequest(http.MethodPost, SentinelURL, strings.NewReader(body))
	if err != nil {
		return "", "", fmt.Errorf("build sentinel request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	req.Header.Set("Origin", "https://sentinel.openai.com")
	req.Header.Set("Referer", "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6")
	req.Header.Set("User-Agent", client.UA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	responseBody, err := fetchSentinelChallenge(func() (int, []byte, error) {
		resp, requestErr := c.Do(req)
		if requestErr != nil {
			return 0, nil, requestErr
		}
		defer resp.Body.Close()
		responseBody, readErr := io.ReadAll(resp.Body)
		return resp.StatusCode, responseBody, readErr
	}, func() ([]byte, error) {
		return fetchSentinelChallengeHeadless(sentinelBrowserRequest{
			body:     body,
			proxyURL: c.ProxyURL(),
		})
	})
	if err != nil {
		return "", "", err
	}
	var challenge SentinelChallenge
	if err := json.Unmarshal(responseBody, &challenge); err != nil {
		return "", "", fmt.Errorf("decode sentinel challenge: %w", err)
	}
	if challenge.Token == "" {
		return "", "", fmt.Errorf("empty sentinel challenge token")
	}
	proof := generator.GenerateRequirementsToken()
	if challenge.ProofOfWork.Required && challenge.ProofOfWork.Seed != "" {
		proof = generator.GeneratePoWToken(challenge.ProofOfWork.Seed, challenge.ProofOfWork.Difficulty)
	}
	result := fmt.Sprintf(`{"p":"%s","t":"","c":"%s","id":"%s","flow":"%s"}`, proof, challenge.Token, deviceID, flow)
	return result, challenge.Token, nil
}

func fetchSentinelChallenge(httpFetch func() (int, []byte, error), browserFetch func() ([]byte, error)) ([]byte, error) {
	status, body, err := httpFetch()
	if err == nil && status == http.StatusOK {
		return body, nil
	}
	if err == nil && status != http.StatusForbidden {
		return nil, fmt.Errorf("sentinel challenge: status %d", status)
	}
	browserBody, browserErr := browserFetch()
	if browserErr != nil {
		if err != nil {
			return nil, fmt.Errorf("sentinel HTTP request failed (%v); headless browser failed: %w", err, browserErr)
		}
		return nil, fmt.Errorf("sentinel challenge blocked (%d); headless browser failed: %w", status, browserErr)
	}
	return browserBody, nil
}
