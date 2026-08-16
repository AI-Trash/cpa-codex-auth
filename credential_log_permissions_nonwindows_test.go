//go:build !windows

package main

import (
	"os"
	"testing"
)

func TestAppendCredentialChange_setsOwnerOnlyMode_whenEnabled(t *testing.T) {
	// Given: an isolated current directory for an account change log.
	t.Chdir(t.TempDir())

	// When: the credential change is appended.
	if err := appendCredentialChange(credentialChange{Email: "user@example.com", Operation: credentialChangePasswordReset, Password: "password"}, true); err != nil {
		t.Fatalf("append credential change: %v", err)
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
