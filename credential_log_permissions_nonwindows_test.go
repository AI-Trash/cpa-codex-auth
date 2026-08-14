//go:build !windows

package main

import (
	"os"
	"testing"
)

func TestSaveCredentialLog_setsOwnerOnlyMode_whenEnabled(t *testing.T) {
	// Given: an isolated current directory for a final credential log.
	t.Chdir(t.TempDir())

	// When: the credential log is saved.
	if err := saveCredentialLog(credentialLog{Email: "user@example.com", Password: "password", TOTPSecret: "totp"}, true); err != nil {
		t.Fatalf("save credential log: %v", err)
	}

	// Then: only the owner has Unix file permissions.
	info, err := os.Stat("cpa-codex-auth.credentials")
	if err != nil {
		t.Fatalf("stat credential log: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("credential log mode = %o, want %o", got, want)
	}
}
