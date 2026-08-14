package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type tokenResult struct {
	AccessToken  string
	AccountID    string
	Email        string
	Expired      time.Time
	IDToken      string
	LastRefresh  time.Time
	RefreshToken string
}

type cpaCredential struct {
	AccessToken  string `json:"access_token"`
	AccountID    string `json:"account_id"`
	Disabled     bool   `json:"disabled"`
	Email        string `json:"email"`
	Expired      string `json:"expired"`
	IDToken      string `json:"id_token"`
	LastRefresh  string `json:"last_refresh"`
	RefreshToken string `json:"refresh_token"`
	Type         string `json:"type"`
	WebSockets   bool   `json:"websockets"`
}

type credentialLog struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret"`
}

func saveCredential(directory string, token tokenResult) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create credential directory: %w", err)
	}
	filename := "codex-" + safeEmailFilename(token.Email) + "-plus.json"
	path := filepath.Join(directory, filename)
	temporaryPath := path + ".tmp"
	credential := cpaCredential{
		AccessToken: token.AccessToken, AccountID: token.AccountID, Disabled: false,
		Email: token.Email, Expired: token.Expired.UTC().Format(time.RFC3339), IDToken: token.IDToken,
		LastRefresh: token.LastRefresh.UTC().Format(time.RFC3339), RefreshToken: token.RefreshToken,
		Type: "codex", WebSockets: true,
	}
	data, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode CPA credential: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(temporaryPath, data, 0o600); err != nil {
		return "", fmt.Errorf("write temporary credential: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("replace credential: %w", err)
	}
	return path, nil
}

type credentialLogRequest struct {
	Token      tokenResult
	Password   string
	TOTPSecret string
	Enabled    bool
}

func saveFinalCredentialLog(request credentialLogRequest) error {
	return saveCredentialLog(credentialLog{
		Email:      request.Token.Email,
		Password:   request.Password,
		TOTPSecret: request.TOTPSecret,
	}, request.Enabled)
}

func saveCredentialLog(log credentialLog, enabled bool) error {
	if !enabled {
		return nil
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credential log: %w", err)
	}
	data = append(data, '\n')
	temporaryFile, err := os.CreateTemp(".", ".cpa-codex-auth.credentials-*")
	if err != nil {
		return fmt.Errorf("create temporary credential log: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)
	if err := secureCredentialLogFile(temporaryFile); err != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("secure temporary credential log: %w", err)
	}
	if _, err := temporaryFile.Write(data); err != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("write temporary credential log: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close temporary credential log: %w", err)
	}
	if err := os.Rename(temporaryPath, "cpa-codex-auth.credentials"); err != nil {
		return fmt.Errorf("replace credential log: %w", err)
	}
	return nil
}

func safeEmailFilename(email string) string {
	return strings.Map(func(character rune) rune {
		if character < 32 || strings.ContainsRune(`<>:"/\\|?*`, character) {
			return '_'
		}
		return character
	}, email)
}
