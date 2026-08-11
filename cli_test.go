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
		"--rotate",
	})

	// When: the command executes with all credential flags.
	err := command.ExecuteContext(context.Background())

	// Then: each named credential reaches the runner.
	if err != nil {
		t.Fatalf("execute command: %v", err)
	}
	if got.email != "person@example.com" || got.password != "password-value" || got.totpSecret != "totp-value" || !got.rotate {
		t.Fatalf("unexpected credentials: %#v", got)
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
