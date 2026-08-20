package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chromedp/chromedp"

	"openai-tool/cpa-codex-auth/internal/browser"
	"openai-tool/cpa-codex-auth/internal/client"
)

const sentinelFrameURL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"

type sentinelBrowserRequest struct {
	body     string
	proxyURL string
}

func sentinelBrowserScript(body string) (string, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode sentinel browser request: %w", err)
	}
	return fmt.Sprintf(`(() => {
			const request = new XMLHttpRequest();
			request.open('POST', '/backend-api/sentinel/req', false);
			request.setRequestHeader('Content-Type', 'text/plain;charset=UTF-8');
			request.send(%s);
			if (request.status !== 200) throw new Error('HTTP ' + request.status);
			return request.responseText;
		})()`, bodyJSON), nil
}

func fetchSentinelChallengeHeadless(request sentinelBrowserRequest) ([]byte, error) {
	executablePath, err := browser.Executable(request.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("resolve Sentinel browser executable: %w", err)
	}

	profileDir, err := os.MkdirTemp("", "cpa-codex-sentinel-")
	if err != nil {
		return nil, fmt.Errorf("create headless browser profile: %w", err)
	}
	defer os.RemoveAll(profileDir)

	opts := sentinelBrowserAllocatorOptions(executablePath, profileDir, request.proxyURL)

	allocatorContext, cancelAllocator := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAllocator()
	browserContext, cancelBrowser := chromedp.NewContext(allocatorContext)
	defer cancelBrowser()
	ctx, cancelTimeout := context.WithTimeout(browserContext, 45*time.Second)
	defer cancelTimeout()

	script, err := sentinelBrowserScript(request.body)
	if err != nil {
		return nil, err
	}

	var result string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(sentinelFrameURL),
		chromedp.Evaluate(script, &result),
	); err != nil {
		return nil, fmt.Errorf("run Sentinel in headless browser: %w", err)
	}
	return []byte(result), nil
}

func sentinelBrowserAllocatorOptions(executablePath, profileDir, proxyURL string) []chromedp.ExecAllocatorOption {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.ExecPath(executablePath),
		chromedp.UserDataDir(profileDir),
		chromedp.UserAgent(client.UA),
		chromedp.WindowSize(1280, 720),
	)
	if proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(proxyURL))
	}
	return opts
}
