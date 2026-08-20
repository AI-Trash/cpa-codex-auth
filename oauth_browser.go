package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"openai-tool/cpa-codex-auth/internal/browser"
	"openai-tool/cpa-codex-auth/internal/client"
)

type chromedpOAuthBrowser struct {
	client          *client.Client
	profileDir      string
	browserContext  context.Context
	cancelBrowser   context.CancelFunc
	cancelAllocator context.CancelFunc
}

func launchOAuthBrowser(ctx context.Context, request oauthBrowserLaunchRequest) (oauthBrowser, error) {
	executablePath, err := browser.Executable(request.Client.ProxyURL())
	if err != nil {
		return nil, fmt.Errorf("resolve OAuth browser executable: %w", err)
	}
	profileDir, err := os.MkdirTemp("", "cpa-oauth-")
	if err != nil {
		return nil, fmt.Errorf("create OAuth browser profile: %w", err)
	}
	opts := oauthBrowserAllocatorOptions(executablePath, profileDir, request.Client.ProxyURL())
	_, browserContext, cancelAllocator, cancelBrowser := newOAuthBrowserContexts(ctx, opts)
	browser := &chromedpOAuthBrowser{
		client:          request.Client,
		profileDir:      profileDir,
		browserContext:  browserContext,
		cancelBrowser:   cancelBrowser,
		cancelAllocator: cancelAllocator,
	}
	if err := browser.syncClientCookies(ctx); err != nil {
		browser.Close()
		return nil, err
	}
	if err := browser.run(ctx, chromedp.Navigate(request.AuthURL)); err != nil {
		browser.Close()
		return nil, fmt.Errorf("run OAuth browser initialization: %w", err)
	}
	if err := browser.syncBrowserCookies(ctx); err != nil {
		browser.Close()
		return nil, err
	}
	return browser, nil
}

func oauthBrowserAllocatorOptions(executablePath, profileDir, proxyURL string) []chromedp.ExecAllocatorOption {
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

func newOAuthBrowserContexts(_ context.Context, opts []chromedp.ExecAllocatorOption) (context.Context, context.Context, context.CancelFunc, context.CancelFunc) {
	allocatorContext, cancelAllocator := chromedp.NewExecAllocator(context.Background(), opts...)
	browserContext, cancelBrowser := chromedp.NewContext(allocatorContext)
	return allocatorContext, browserContext, cancelAllocator, cancelBrowser
}

func (b *chromedpOAuthBrowser) Fetch(ctx context.Context, request oauthBrowserFetchRequest) (*http.Response, error) {
	headers := filterOAuthBrowserHeaders(request.Header)
	payload, err := json.Marshal(struct {
		Method          string            `json:"method"`
		URL             string            `json:"url"`
		Header          map[string]string `json:"header"`
		Body            string            `json:"body"`
		FollowRedirects bool              `json:"followRedirects"`
	}{
		Method:          request.Method,
		URL:             request.URL,
		Header:          headers,
		Body:            string(request.Body),
		FollowRedirects: request.FollowRedirects,
	})
	if err != nil {
		return nil, fmt.Errorf("encode browser auth request: %w", err)
	}
	var result struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	script := fmt.Sprintf(`(async () => {
		const request = %s;
		const response = await fetch(request.url, {
			method: request.method,
			headers: request.header,
			body: request.body || undefined,
			credentials: "include",
			redirect: request.followRedirects ? "follow" : "manual"
		});
		return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body: await response.text() };
	})()`, payload)
	if err := b.run(ctx, chromedp.Evaluate(script, &result, func(params *runtime.EvaluateParams) *runtime.EvaluateParams {
		return params.WithAwaitPromise(true)
	})); err != nil {
		return nil, fmt.Errorf("run browser auth request: %w", err)
	}
	if err := b.syncBrowserCookies(ctx); err != nil {
		return nil, err
	}
	header := make(http.Header, len(result.Headers))
	for name, value := range result.Headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode: browserFetchStatus(result.Status, request.FollowRedirects),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(result.Body)),
	}, nil
}

func browserFetchStatus(status int, followRedirects bool) int {
	if !followRedirects && status == 0 {
		return http.StatusFound
	}
	return status
}

func filterOAuthBrowserHeaders(headers http.Header) map[string]string {
	allowed := []string{
		"Accept",
		"Content-Type",
		"Openai-Sentinel-Token",
		"Openai-Sentinel-So-Token",
	}
	filtered := make(map[string]string, len(allowed))
	for _, name := range allowed {
		if values := headers.Values(name); len(values) > 0 {
			filtered[name] = strings.Join(values, ", ")
		}
	}
	return filtered
}

func (b *chromedpOAuthBrowser) FollowRedirects(ctx context.Context, request oauthBrowserRedirectRequest) (string, error) {
	expected, err := url.Parse(request.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("parse expected OAuth callback: %w", err)
	}
	callbackURLs := make(chan string, 1)
	chromedp.ListenTarget(b.browserContext, func(event any) {
		requestEvent, ok := event.(*network.EventRequestWillBeSent)
		if !ok || requestEvent.Request == nil {
			return
		}
		callback, parseErr := url.Parse(requestEvent.Request.URL)
		if parseErr != nil || callback.Scheme != expected.Scheme || callback.Host != expected.Host || callback.Path != expected.Path {
			return
		}
		select {
		case callbackURLs <- callback.String():
		default:
		}
	})
	runErr := b.run(ctx, network.Enable(), chromedp.Navigate(request.URL))
	select {
	case callbackURL := <-callbackURLs:
		if err := b.syncBrowserCookies(ctx); err != nil {
			return "", err
		}
		return callbackURL, nil
	default:
	}
	if runErr != nil {
		return "", fmt.Errorf("run browser OAuth redirects: %w", runErr)
	}
	return "", fmt.Errorf("browser OAuth redirects did not reach localhost callback")
}

func (b *chromedpOAuthBrowser) Close() {
	b.cancelBrowser()
	b.cancelAllocator()
	os.RemoveAll(b.profileDir)
}

func (b *chromedpOAuthBrowser) run(ctx context.Context, actions ...chromedp.Action) error {
	actionContext, cancel := context.WithTimeout(b.browserContext, 45*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	return chromedp.Run(actionContext, actions...)
}

func (b *chromedpOAuthBrowser) syncClientCookies(ctx context.Context) error {
	cookies := b.client.CookiesForURL(authBaseURL)
	actions := make([]chromedp.Action, 0, len(cookies))
	for _, cookie := range cookies {
		cookie := cookie
		actions = append(actions, chromedp.ActionFunc(func(actionContext context.Context) error {
			params := network.SetCookie(cookie.Name, cookie.Value).
				WithDomain(cookie.Domain).
				WithPath(cookie.Path).
				WithHTTPOnly(cookie.HTTPOnly).
				WithSecure(cookie.Secure)
			if cookie.SameSite != "" {
				params = params.WithSameSite(network.CookieSameSite(cookie.SameSite))
			}
			if cookie.Expires != nil {
				expires := cdp.TimeSinceEpoch(*cookie.Expires)
				params = params.WithExpires(&expires)
			}
			return params.Do(actionContext)
		}))
	}
	if len(actions) == 0 {
		return nil
	}
	return b.run(ctx, actions...)
}

func (b *chromedpOAuthBrowser) syncBrowserCookies(ctx context.Context) error {
	var cookies []*network.Cookie
	if err := b.run(ctx, chromedp.ActionFunc(func(actionContext context.Context) error {
		var err error
		cookies, err = network.GetCookies().WithURLs([]string{authBaseURL}).Do(actionContext)
		return err
	})); err != nil {
		return fmt.Errorf("get OAuth browser cookies: %w", err)
	}
	for _, cookie := range cookies {
		var expires *time.Time
		if !cookie.Session {
			seconds := int64(cookie.Expires)
			value := time.Unix(seconds, int64((cookie.Expires-float64(seconds))*float64(time.Second))).UTC()
			expires = &value
		}
		b.client.StoreCookie(authBaseURL, client.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   strings.TrimPrefix(cookie.Domain, "."),
			Path:     cookie.Path,
			HTTPOnly: cookie.HTTPOnly,
			Secure:   cookie.Secure,
			SameSite: string(cookie.SameSite),
			Expires:  expires,
		})
	}
	return nil
}
