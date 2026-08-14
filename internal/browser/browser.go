package browser

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/go-rod/rod/lib/launcher"
)

var (
	executableOnce sync.Once
	executablePath string
	executableErr  error
)

func Executable(proxyURL string) (string, error) {
	executableOnce.Do(func() {
		executablePath, executableErr = resolveExecutable(findInstalledExecutable, announceChromiumDownload, func() (string, error) {
			return downloadChromium(proxyURL)
		})
	})
	return executablePath, executableErr
}

func resolveExecutable(lookPath func(string) (string, error), notice func(error), download func() (string, error)) (string, error) {
	path, err := lookPath("google-chrome")
	if err == nil {
		return path, nil
	}
	notice(err)
	path, err = download()
	if err != nil {
		return "", fmt.Errorf("download Chromium: %w", err)
	}
	return path, nil
}

func announceChromiumDownload(lookupErr error) {
	cacheRoot, cacheErr := browserCacheDir()
	if cacheErr != nil {
		cacheRoot = fmt.Sprintf("unavailable: %v", cacheErr)
	}
	fmt.Fprintf(os.Stderr, "No installed Chromium browser found (%v). Downloading it once on first use may take a while. Cache: %s. Future runs reuse it.\n", lookupErr, cacheRoot)
}

func findInstalledExecutable(_ string) (string, error) {
	path, found := launcher.LookPath()
	if !found {
		return "", errors.New("installed Chromium browser not found")
	}
	return path, nil
}

func downloadChromium(proxyURL string) (string, error) {
	switch runtime.GOOS + "_" + runtime.GOARCH {
	case "darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64":
	default:
		return "", fmt.Errorf("unsupported Chromium download platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	cacheRoot, err := browserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find browser cache directory: %w", err)
	}
	browser := launcher.NewBrowser()
	browser.RootDir = cacheRoot
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return "", errors.New("invalid browser download proxy URL")
		}
		if proxy.Scheme == "http" || proxy.Scheme == "https" {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(proxy)
			browser.HTTPClient = &http.Client{Transport: transport}
		}
	}
	path, err := browser.Get()
	if err != nil {
		return "", err
	}
	return path, nil
}

func browserCacheDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "cpa-codex-auth", "chromium"), nil
}
