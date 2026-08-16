package main

import (
	"encoding/json"
	"fmt"
	"io"
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

const (
	credentialChangeTOTPDisabled  = "totp_disabled"
	credentialChangeTOTPEnrolled  = "totp_enrolled"
	credentialChangePasswordSet   = "password_set"
	credentialChangePasswordReset = "password_reset"
)

type credentialChange struct {
	OccurredAt time.Time `json:"occurred_at"`
	Email      string    `json:"email"`
	Operation  string    `json:"operation"`
	FactorID   string    `json:"factor_id,omitempty"`
	Password   string    `json:"password,omitempty"`
	TOTPSecret string    `json:"totp_secret,omitempty"`
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

func appendCredentialChange(change credentialChange, enabled bool) error {
	if !enabled {
		return nil
	}
	if change.OccurredAt.IsZero() {
		change.OccurredAt = time.Now().UTC()
	}
	data, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("encode credential change: %w", err)
	}
	data = append(data, '\n')
	if info, statErr := os.Lstat("cpa-codex-auth.credentials"); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential change log is a symbolic link")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect credential change log: %w", statErr)
	}
	file, err := os.OpenFile("cpa-codex-auth.credentials", credentialLogOpenFlags, 0o600)
	if err != nil {
		return fmt.Errorf("open credential change log: %w", err)
	}
	if err := secureCredentialLogFile(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure credential change log: %w", err)
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("append credential change: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close credential change log: %w", closeErr)
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
