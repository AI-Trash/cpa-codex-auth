//go:build !windows

package main

import "os"

func secureCredentialLogFile(file *os.File) error {
	return file.Chmod(0o600)
}
