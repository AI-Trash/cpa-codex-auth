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
	rotate     rotationTargets
}

type rotationTargets uint8

const (
	rotateTOTP rotationTargets = 1 << iota
	rotatePassword
)

func parseRotationTargets(value string) (rotationTargets, error) {
	var targets rotationTargets
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		switch item {
		case "totp":
			targets |= rotateTOTP
		case "password":
			targets |= rotatePassword
		case "":
			return 0, fmt.Errorf("--rotate contains an empty item")
		default:
			return 0, fmt.Errorf("--rotate contains unknown credential %q; expected totp or password", item)
		}
	}
	return targets, nil
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
	var rotate string
	var proxy string
	var outputDirectory string
	command := &cobra.Command{
		Use:           "cpa-codex-auth --email <email> [--password <password>] [--totpsecret <secret>] [--rotate <totp,password>]",
		Short:         "Configure an OpenAI account and save a CPA Codex credential",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			credentials := startupCredentials{
				email:      strings.TrimSpace(email),
				password:   password,
				totpSecret: strings.TrimSpace(totpSecret),
				rotate:     0,
			}
			if credentials.email == "" {
				return fmt.Errorf("--email is required")
			}
			if command.Flags().Changed("rotate") {
				var err error
				credentials.rotate, err = parseRotationTargets(rotate)
				if err != nil {
					return err
				}
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
	command.Flags().StringVarP(&email, "email", "e", "", "OpenAI account email address")
	command.Flags().StringVarP(&password, "password", "p", "", "OpenAI account password")
	command.Flags().StringVarP(&totpSecret, "totpsecret", "t", "", "OpenAI account TOTP secret")
	command.Flags().StringVarP(&rotate, "rotate", "r", "", "comma-separated credentials to replace: totp, password")
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
