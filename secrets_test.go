package main

import (
	"strings"
	"testing"
)

func TestGeneratePassword_contains_required_character_classes(t *testing.T) {
	// Given: the secure password generator.
	// When: a password is generated.
	password, err := generatePassword()

	// Then: it has the configured length and every required character class.
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	if len(password) != 20 {
		t.Fatalf("unexpected password length: %d", len(password))
	}
	for _, alphabet := range []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*.-"} {
		if !strings.ContainsAny(password, alphabet) {
			t.Fatalf("password lacks characters from %q", alphabet)
		}
	}
}
