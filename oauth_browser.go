package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"openai-tool/cpa-codex-auth/internal/client"
)

func initializeOAuthSessionBrowser(c *client.Client, authURL, deviceID string) error {
	profileDir, err := os.MkdirTemp("", "cpa-oauth-")
	if err != nil {
		return fmt.Errorf("create OAuth browser profile: %w", err)
	}
	defer os.RemoveAll(profileDir)

	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.UserDataDir(profileDir),
		chromedp.UserAgent(client.UA),
		chromedp.WindowSize(1280, 720),
	)
	if proxyURL := c.ProxyURL(); proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(proxyURL))
	}

	allocatorContext, cancelAllocator := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAllocator()
	browserContext, cancelBrowser := chromedp.NewContext(allocatorContext)
	defer cancelBrowser()
	ctx, cancelTimeout := context.WithTimeout(browserContext, 45*time.Second)
	defer cancelTimeout()

	var browserCookies []*network.Cookie
	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetCookie("oai-did", deviceID).WithURL(authBaseURL).Do(ctx)
		}),
		chromedp.Navigate(authURL),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var getErr error
			browserCookies, getErr = network.GetCookies().WithURLs([]string{authBaseURL}).Do(ctx)
			return getErr
		}),
	); err != nil {
		return fmt.Errorf("run OAuth browser initialization: %w", err)
	}

	for _, cookie := range browserCookies {
		domain := strings.TrimPrefix(cookie.Domain, ".")
		if domain == "" {
			return fmt.Errorf("OAuth browser cookie %q has no domain", cookie.Name)
		}
		c.SetCookie("https://"+domain, cookie.Name, cookie.Value)
	}
	if c.GetCookieValue("oai-client-auth-session") == "" {
		return fmt.Errorf("OAuth browser initialization did not create oai-client-auth-session")
	}
	return nil
}
