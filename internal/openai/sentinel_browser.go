package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/chromedp/chromedp"

	"openai-tool/cpa-codex-auth/internal/client"
)

const sentinelFrameURL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"

type sentinelBrowserRequest struct {
	body     string
	proxyURL string
}

func fetchSentinelChallengeHeadless(request sentinelBrowserRequest) ([]byte, error) {
	profileDir, err := os.MkdirTemp("", "cpa-codex-sentinel-")
	if err != nil {
		return nil, fmt.Errorf("create headless browser profile: %w", err)
	}
	defer os.RemoveAll(profileDir)

	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.UserDataDir(profileDir),
		chromedp.UserAgent(client.UA),
		chromedp.WindowSize(1280, 720),
	)
	if request.proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(request.proxyURL))
	}

	allocatorContext, cancelAllocator := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAllocator()
	browserContext, cancelBrowser := chromedp.NewContext(allocatorContext)
	defer cancelBrowser()
	ctx, cancelTimeout := context.WithTimeout(browserContext, 45*time.Second)
	defer cancelTimeout()

	bodyJSON, err := json.Marshal(request.body)
	if err != nil {
		return nil, fmt.Errorf("encode sentinel browser request: %w", err)
	}
	script := fmt.Sprintf(`(() => {
		const request = new XMLHttpRequest();
		request.open('POST', '/backend-api/sentinel/req', false);
		request.setRequestHeader('Content-Type', 'text/plain;charset=UTF-8');
		request.send(%s);
		if (request.status !== 200) throw new Error('HTTP ' + request.status + ': ' + request.responseText);
		return request.responseText;
	})()`, bodyJSON)

	var result string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(sentinelFrameURL),
		chromedp.Evaluate(script, &result),
	); err != nil {
		return nil, fmt.Errorf("run Sentinel in headless browser: %w", err)
	}
	return []byte(result), nil
}
