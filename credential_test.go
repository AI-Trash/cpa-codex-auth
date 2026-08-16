package main

import (
	"bufio"
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

func TestAppendCredentialChange_preservesEveryOperation(t *testing.T) {
	// Given: two successful account changes in one working directory.
	t.Chdir(t.TempDir())
	first := credentialChange{Email: "user@example.com", Operation: credentialChangeTOTPEnrolled, TOTPSecret: "NEW_TOTP"}
	second := credentialChange{Email: "user@example.com", Operation: credentialChangePasswordReset, Password: "new-password"}

	// When: each change is recorded.
	if err := appendCredentialChange(first, true); err != nil {
		t.Fatalf("append first change: %v", err)
	}
	if err := appendCredentialChange(second, true); err != nil {
		t.Fatalf("append second change: %v", err)
	}

	// Then: both records remain in order instead of the second replacing the first.
	file, err := os.Open("cpa-codex-auth.credentials")
	if err != nil {
		t.Fatalf("open credential change log: %v", err)
	}
	defer file.Close()
	var changes []credentialChange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var change credentialChange
		if err := json.Unmarshal(scanner.Bytes(), &change); err != nil {
			t.Fatalf("decode change: %v", err)
		}
		changes = append(changes, change)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan changes: %v", err)
	}
	if len(changes) != 2 || changes[0].Operation != first.Operation || changes[0].TOTPSecret != first.TOTPSecret || changes[1].Operation != second.Operation || changes[1].Password != second.Password {
		t.Fatalf("credential changes = %#v", changes)
	}
	if changes[0].OccurredAt.IsZero() || changes[1].OccurredAt.IsZero() {
		t.Fatalf("credential change timestamps missing: %#v", changes)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat("cpa-codex-auth.credentials")
		if statErr != nil {
			t.Fatalf("stat credential change log: %v", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credential change log mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestAppendCredentialChange_writesNothingWhenDisabled(t *testing.T) {
	// Given: an account change with logging disabled.
	t.Chdir(t.TempDir())

	// When: the change is offered to the log.
	if err := appendCredentialChange(credentialChange{Email: "user@example.com", Operation: credentialChangePasswordReset, Password: "secret"}, false); err != nil {
		t.Fatalf("append disabled change: %v", err)
	}

	// Then: login-only and opted-out runs leave no credential log.
	if _, err := os.Stat("cpa-codex-auth.credentials"); !os.IsNotExist(err) {
		t.Fatalf("credential change log exists or stat failed: %v", err)
	}
}

func TestAppendCredentialChange_rejectsSymbolicLink(t *testing.T) {
	// Given: the audit-log path is a symbolic link to another file.
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	target := filepath.Join(workingDirectory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Symlink(target, "cpa-codex-auth.credentials"); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}

	// When: a credential change is appended.
	err := appendCredentialChange(credentialChange{Email: "user@example.com", Operation: credentialChangePasswordReset, Password: "password"}, true)

	// Then: the linked target remains untouched.
	if err == nil {
		t.Fatal("append through symbolic link unexpectedly succeeded")
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if len(data) != 0 {
		t.Fatalf("symbolic-link target was modified: %q", data)
	}
}
