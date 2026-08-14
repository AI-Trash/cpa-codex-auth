package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSaveCredential_replaces_stable_CPA_file(t *testing.T) {
	// Given: two token snapshots for the same account.
	directory := t.TempDir()
	first := tokenResult{AccessToken: "first", AccountID: "acct", Email: "a+b@example.com", Expired: time.Now().UTC(), IDToken: "id", LastRefresh: time.Now().UTC(), RefreshToken: "refresh"}
	second := first
	second.AccessToken = "second"

	// When: both snapshots are saved.
	firstPath, err := saveCredential(directory, first)
	if err != nil {
		t.Fatalf("save first credential: %v", err)
	}
	secondPath, err := saveCredential(directory, second)
	if err != nil {
		t.Fatalf("save second credential: %v", err)
	}

	// Then: the stable CPA filename is reused and contains the replacement data.
	wantPath := filepath.Join(directory, "codex-a+b@example.com-plus.json")
	if firstPath != wantPath || secondPath != wantPath {
		t.Fatalf("unexpected paths: %q, %q", firstPath, secondPath)
	}
	data, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	if saved["access_token"] != "second" || saved["type"] != "codex" || saved["websockets"] != true || saved["disabled"] != false {
		t.Fatalf("unexpected CPA credential: %#v", saved)
	}
}

func TestSaveCredentialLog_writesFinalCredentialsToCurrentDirectory(t *testing.T) {
	// Given: final credentials and an isolated current directory.
	t.Chdir(t.TempDir())
	credentials := startupCredentials{
		email:                "user@example.com",
		password:             "final-password",
		totpSecret:           "FINAL_TOTP",
		credentialLogEnabled: true,
	}

	// When: the credential log is saved.
	if err := saveCredentialLog(credentialLog{Email: credentials.email, Password: credentials.password, TOTPSecret: credentials.totpSecret}, credentials.credentialLogEnabled); err != nil {
		t.Fatalf("save credential log: %v", err)
	}

	// Then: the dedicated cwd file contains only the final credential fields.
	path := filepath.Join(".", "cpa-codex-auth.credentials")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credential log: %v", err)
	}
	var saved map[string]string
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode credential log: %v", err)
	}
	if saved["email"] != credentials.email || saved["password"] != credentials.password || saved["totp_secret"] != credentials.totpSecret {
		t.Fatalf("unexpected credential log: %#v", saved)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credential log: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("credential log mode = %o, want 600", info.Mode().Perm())
	}
	if matches, err := filepath.Glob(".cpa-codex-auth.credentials-*"); err != nil || len(matches) != 0 {
		t.Fatalf("temporary credential files remain: %v", matches)
	}
}

func TestSaveCredentialLog_writesNothingWhenDisabled(t *testing.T) {
	// Given: final credentials with logging disabled in an isolated cwd.
	t.Chdir(t.TempDir())
	credentials := startupCredentials{email: "user@example.com", password: "secret", totpSecret: "totp"}

	// When: the credential log is requested.
	if err := saveCredentialLog(credentialLog{Email: credentials.email, Password: credentials.password, TOTPSecret: credentials.totpSecret}, credentials.credentialLogEnabled); err != nil {
		t.Fatalf("save disabled credential log: %v", err)
	}

	// Then: no dedicated secret file is created.
	if _, err := os.Stat("cpa-codex-auth.credentials"); !os.IsNotExist(err) {
		t.Fatalf("credential log exists or stat failed: %v", err)
	}
}

func TestSaveCredentialLog_removesTemporaryFileWhenWriteFails(t *testing.T) {
	// Given: a cwd where the target path is an unwritable directory.
	t.Chdir(t.TempDir())
	if err := os.Mkdir("cpa-codex-auth.credentials", 0o700); err != nil {
		t.Fatalf("create blocking path: %v", err)
	}
	credentials := startupCredentials{email: "user@example.com", password: "secret", totpSecret: "totp", credentialLogEnabled: true}

	// When: atomic replacement cannot complete.
	if err := saveCredentialLog(credentialLog{Email: credentials.email, Password: credentials.password, TOTPSecret: credentials.totpSecret}, credentials.credentialLogEnabled); err == nil {
		t.Fatal("save credential log unexpectedly succeeded")
	}

	// Then: no temporary secret file remains.
	matches, err := filepath.Glob(".cpa-codex-auth.credentials-*")
	if err != nil {
		t.Fatalf("find temporary credential files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary credential files remain: %v", matches)
	}
}

func TestSaveCredentialLog_replacesExistingFinalValues(t *testing.T) {
	// Given: two successful finalized credential snapshots in the same directory.
	t.Chdir(t.TempDir())
	first := credentialLog{Email: "user@example.com", Password: "first-password", TOTPSecret: "FIRST_TOTP"}
	second := credentialLog{Email: "user@example.com", Password: "second-password", TOTPSecret: "SECOND_TOTP"}
	if err := saveCredentialLog(first, true); err != nil {
		t.Fatalf("save first credential log: %v", err)
	}

	// When: the final values are written again.
	if err := saveCredentialLog(second, true); err != nil {
		t.Fatalf("replace credential log: %v", err)
	}

	// Then: the stable file contains only the second complete snapshot.
	data, err := os.ReadFile("cpa-codex-auth.credentials")
	if err != nil {
		t.Fatalf("read replacement credential log: %v", err)
	}
	var saved credentialLog
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode replacement credential log: %v", err)
	}
	if saved != second {
		t.Fatalf("replacement credential log = %#v, want %#v", saved, second)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat("cpa-codex-auth.credentials")
		if statErr != nil {
			t.Fatalf("stat replacement credential log: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("replacement credential log mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestSaveFinalCredentialLog_writesPostRotationValues(t *testing.T) {
	// Given: startup values differ from the generated final credentials.
	t.Chdir(t.TempDir())
	request := credentialLogRequest{
		Token:      tokenResult{Email: "final@example.com"},
		Password:   "final-password",
		TOTPSecret: "FINAL_TOTP",
		Enabled:    true,
	}

	// When: the post-authentication log is written.
	if err := saveFinalCredentialLog(request); err != nil {
		t.Fatalf("save final credential log: %v", err)
	}

	// Then: only the post-rotation values reach the persistent log.
	data, err := os.ReadFile("cpa-codex-auth.credentials")
	if err != nil {
		t.Fatalf("read final credential log: %v", err)
	}
	var saved credentialLog
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode final credential log: %v", err)
	}
	if saved.Email != request.Token.Email || saved.Password != request.Password || saved.TOTPSecret != request.TOTPSecret {
		t.Fatalf("final credential log = %#v", saved)
	}
}
