//go:build !windows

package main

import "syscall"

const credentialLogOpenFlags = syscall.O_CREAT | syscall.O_WRONLY | syscall.O_APPEND | syscall.O_NOFOLLOW
