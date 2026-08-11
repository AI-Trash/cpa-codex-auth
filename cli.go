package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

type startupCredentials struct {
	email      string
	password   string
	totpSecret string
	rotate     bool
}

type runFunc func(context.Context, startupCredentials, *prompter) error

type prompter struct {
	scanner         *bufio.Scanner
	output          io.Writer
	proxy           string
	outputDirectory string
}

func newRootCommand(input io.Reader, output io.Writer, run runFunc) *cobra.Command {
	var email string
	var password string
	var totpSecret string
	var rotate bool
	var proxy string
	var outputDirectory string
	command := &cobra.Command{
		Use:           "cpa-codex-auth --email <email> [--password <password>] [--totpsecret <secret>]",
		Short:         "Configure an OpenAI account and save a CPA Codex credential",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			credentials := startupCredentials{
				email:      strings.TrimSpace(email),
				password:   password,
				totpSecret: strings.TrimSpace(totpSecret),
				rotate:     rotate,
			}
			if credentials.email == "" {
				return fmt.Errorf("--email is required")
			}
			if run == nil {
				return nil
			}
			prompt := &prompter{scanner: bufio.NewScanner(input), output: output}
			prompt.proxy = proxy
			prompt.outputDirectory = outputDirectory
			return run(command.Context(), credentials, prompt)
		},
	}
	command.SetOut(output)
	command.SetErr(output)
	command.Flags().StringVar(&email, "email", "", "OpenAI account email address")
	command.Flags().StringVar(&password, "password", "", "OpenAI account password")
	command.Flags().StringVar(&totpSecret, "totpsecret", "", "OpenAI account TOTP secret")
	command.Flags().BoolVar(&rotate, "rotate", false, "replace the account password and TOTP secret")
	command.Flags().StringVar(&proxy, "proxy", "", "HTTP or SOCKS proxy URL")
	command.Flags().StringVarP(&outputDirectory, "output", "o", ".", "credential output directory")
	return command
}

func (p *prompter) ask(label string) (string, error) {
	if _, err := fmt.Fprint(p.output, label); err != nil {
		return "", fmt.Errorf("write prompt: %w", err)
	}
	if !p.scanner.Scan() {
		if err := p.scanner.Err(); err != nil {
			return "", fmt.Errorf("read prompt: %w", err)
		}
		return "", io.EOF
	}
	return strings.TrimSpace(p.scanner.Text()), nil
}

func (p *prompter) askRequired(label string) (string, error) {
	for {
		value, err := p.ask(label)
		if err != nil {
			return "", err
		}
		if value != "" {
			return value, nil
		}
	}
}
