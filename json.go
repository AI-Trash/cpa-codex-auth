package main

import (
	"encoding/json"
	"fmt"
	"io"
)

func decodeJSON(reader io.Reader, target any) error {
	if err := json.NewDecoder(reader).Decode(target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}
