//go:build windows

package main

import "os"

const credentialLogOpenFlags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
