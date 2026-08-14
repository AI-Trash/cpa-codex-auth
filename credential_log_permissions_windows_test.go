//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSaveCredentialLog_setsProtectedCurrentUserDACL_whenEnabled(t *testing.T) {
	// Given: an isolated current directory for a final credential log.
	t.Chdir(t.TempDir())

	// When: the credential log is saved.
	if err := saveCredentialLog(credentialLog{Email: "user@example.com", Password: "password", TOTPSecret: "totp"}, true); err != nil {
		t.Fatalf("save credential log: %v", err)
	}

	// Then: its DACL is protected and grants only the current user full control.
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current token user: %v", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		"cpa-codex-auth.credentials",
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("get credential log security descriptor: %v", err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf("get credential log DACL control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("credential log DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("get credential log DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("credential log has no DACL")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("credential log ACE count = %d, want 1", dacl.AceCount)
	}
	wantDescriptor, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatalf("build expected credential log DACL: %v", err)
	}
	wantACE := strings.TrimPrefix(wantDescriptor.String(), "D:")
	if got := descriptor.String(); !strings.HasSuffix(got, wantACE) {
		t.Fatalf("credential log DACL = %q, want ACE %q", got, wantACE)
	}
}
