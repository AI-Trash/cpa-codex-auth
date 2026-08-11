package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveCredential_replaces_stable_CPA_file(t *testing.T) {
	// Given: two token snapshots for the same account.
	directory := t.TempDir()
	first := tokenResult{AccessToken: "first", AccountID: "acct", Email: "a+b@example.com", Expired: time.Now().UTC(), IDToken: "id", LastRefresh: time.Now().UTC(), RefreshToken: "refresh"}
	second := first
	second.AccessToken = "second"

	// When: both snapshots are saved.
	firstPath, err := saveCredential(directory, first)
	if err != nil {
		t.Fatalf("save first credential: %v", err)
	}
	secondPath, err := saveCredential(directory, second)
	if err != nil {
		t.Fatalf("save second credential: %v", err)
	}

	// Then: the stable CPA filename is reused and contains the replacement data.
	wantPath := filepath.Join(directory, "codex-a+b@example.com-plus.json")
	if firstPath != wantPath || secondPath != wantPath {
		t.Fatalf("unexpected paths: %q, %q", firstPath, secondPath)
	}
	data, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	if saved["access_token"] != "second" || saved["type"] != "codex" || saved["websockets"] != true || saved["disabled"] != false {
		t.Fatalf("unexpected CPA credential: %#v", saved)
	}
}
