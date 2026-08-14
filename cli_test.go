package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI_acceptsNamedCredentials_whenFlagsAreGiven(t *testing.T) {
	// Given: a runner that records parsed startup credentials.
	var got startupCredentials
	run := func(_ context.Context, credentials startupCredentials, _ *prompter) error {
		got = credentials
		return nil
	}
	stdout := new(bytes.Buffer)
	command := newRootCommand(strings.NewReader(""), stdout, run)
	command.SetArgs([]string{
		"--email", "person@example.com",
		"--password", "password-value",
		"--totpsecret", "totp-value",
		"--rotate", "password,totp",
	})

	// When: the command executes with all credential flags.
	err := command.ExecuteContext(context.Background())

	// Then: each named credential reaches the runner.
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if got.email != "person@example.com" || got.password != "password-value" || got.totpSecret != "totp-value" || got.rotate != (rotateTOTP|rotatePassword) {
		t.Fatalf("unexpected credentials: %#v", got)
	}
}

func TestCLI_acceptsShorthandCredentials_whenFlagsAreGiven(t *testing.T) {
	// Given: a runner that records parsed startup credentials.
	var got startupCredentials
	run := func(_ context.Context, credentials startupCredentials, _ *prompter) error {
		got = credentials
		return nil
	}
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), run)
	command.SetArgs([]string{"-e", "person@example.com", "-p", "password-value", "-t", "totp-value", "-r", "totp"})

	// When: the command executes with shorthand flags.
	err := command.ExecuteContext(context.Background())

	// Then: shorthands reach the runner with parsed values.
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if got.email != "person@example.com" || got.password != "password-value" || got.totpSecret != "totp-value" || got.rotate != rotateTOTP {
		t.Fatalf("unexpected credentials: %#v", got)
	}
}

func TestCLI_rejectsInvalidRotateValues(t *testing.T) {
	// Given: a root command with an invalid rotation target.
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), nil)
	command.SetArgs([]string{"--email", "person@example.com", "--rotate", "totp,,password"})

	// When: the command executes.
	err := command.ExecuteContext(context.Background())

	// Then: the invalid empty item is rejected.
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty rotate item error, got %v", err)
	}
}

func TestCLI_rejectsUnknownRotateValues(t *testing.T) {
	// Given: a root command with an unknown rotation target.
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), nil)
	command.SetArgs([]string{"--email", "person@example.com", "--rotate", "totp,email"})

	// When: the command executes.
	err := command.ExecuteContext(context.Background())

	// Then: the unknown item is rejected with the accepted values.
	if err == nil || !strings.Contains(err.Error(), "unknown credential") || !strings.Contains(err.Error(), "totp or password") {
		t.Fatalf("expected unknown rotate item error, got %v", err)
	}
}

func TestCLI_rejectsRotateWithoutValue(t *testing.T) {
	// Given: a root command with rotate missing its value.
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), nil)
	command.SetArgs([]string{"--email", "person@example.com", "--rotate"})

	// When: the command executes.
	err := command.ExecuteContext(context.Background())

	// Then: Cobra rejects the missing flag value.
	if err == nil {
		t.Fatal("expected missing rotate value error")
	}
}

func TestCLI_rejectsExplicitlyEmptyRotateValue(t *testing.T) {
	// Given: a root command with an explicitly empty rotate value.
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), nil)
	command.SetArgs([]string{"--email", "person@example.com", "--rotate="})

	// When: the command executes.
	err := command.ExecuteContext(context.Background())

	// Then: the explicit empty value is rejected.
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty rotate value error, got %v", err)
	}
}

func TestCLI_rejectsPositionalCredentials(t *testing.T) {
	// Given: a root command.
	command := newRootCommand(strings.NewReader(""), new(bytes.Buffer), nil)
	command.SetArgs([]string{"a@example.com", "password", "secret"})

	// When: credentials are supplied positionally.
	err := command.ExecuteContext(context.Background())

	// Then: Cobra rejects the old invocation style.
	if err == nil {
		t.Fatal("expected argument validation error")
	}
}
