package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func generatePassword() (string, error) {
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const digits = "0123456789"
	const special = "!@#$%^&*.-"
	const all = lower + upper + digits + special

	password := make([]byte, 20)
	classes := []string{lower, upper, digits, special}
	for index, alphabet := range classes {
		character, err := secureCharacter(alphabet)
		if err != nil {
			return "", err
		}
		password[index] = character
	}
	for index := len(classes); index < len(password); index++ {
		character, err := secureCharacter(all)
		if err != nil {
			return "", err
		}
		password[index] = character
	}
	for index := len(password) - 1; index > 0; index-- {
		choice, err := rand.Int(rand.Reader, big.NewInt(int64(index+1)))
		if err != nil {
			return "", fmt.Errorf("shuffle password: %w", err)
		}
		other := int(choice.Int64())
		password[index], password[other] = password[other], password[index]
	}
	return string(password), nil
}

func secureCharacter(alphabet string) (byte, error) {
	choice, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
	if err != nil {
		return 0, fmt.Errorf("generate password character: %w", err)
	}
	return alphabet[choice.Int64()], nil
}
