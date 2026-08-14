package browser

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveExecutable_whenChromeIsInstalled_skipsDownload(t *testing.T) {
	// Given: the executable lookup finds an installed Chrome binary.
	downloadCalls := 0
	lookPath := func(name string) (string, error) {
		if name != "google-chrome" {
			t.Fatalf("lookPath name = %q, want google-chrome", name)
		}
		return "/installed/chrome", nil
	}
	download := func() (string, error) {
		downloadCalls++
		return "", errors.New("download should not run")
	}

	// When: the browser executable is resolved.
	path, err := resolveExecutable(lookPath, download)

	// Then: the installed binary is returned without downloading Chromium.
	if err != nil {
		t.Fatalf("resolveExecutable() error = %v", err)
	}
	if path != "/installed/chrome" {
		t.Fatalf("path = %q, want /installed/chrome", path)
	}
	if downloadCalls != 0 {
		t.Fatalf("download calls = %d, want 0", downloadCalls)
	}
}

func TestResolveExecutable_whenChromeIsMissing_downloadsChromium(t *testing.T) {
	// Given: no installed Chrome executable is available.
	downloadCalls := 0
	lookPath := func(string) (string, error) { return "", errors.New("not found") }
	download := func() (string, error) {
		downloadCalls++
		return "/cache/chromium", nil
	}

	// When: the browser executable is resolved.
	path, err := resolveExecutable(lookPath, download)

	// Then: Chromium is downloaded once and its cached path is returned.
	if err != nil {
		t.Fatalf("resolveExecutable() error = %v", err)
	}
	if path != "/cache/chromium" {
		t.Fatalf("path = %q, want /cache/chromium", path)
	}
	if downloadCalls != 1 {
		t.Fatalf("download calls = %d, want 1", downloadCalls)
	}
}

func TestResolveExecutable_whenDownloadFails_wrapsError(t *testing.T) {
	// Given: no installed Chrome executable and a failed Chromium download.
	wantErr := errors.New("disk full")
	lookPath := func(string) (string, error) { return "", errors.New("not found") }
	download := func() (string, error) { return "", wantErr }

	// When: the browser executable is resolved.
	_, err := resolveExecutable(lookPath, download)

	// Then: the download error is preserved with resolver context.
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "download Chromium") {
		t.Fatalf("error = %q, want download context", err)
	}
}
