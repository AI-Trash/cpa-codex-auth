package client

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

// Client wraps tls-client with manual cookie management.
type Client struct {
	tls      tls_client.HttpClient
	cookies  map[string]map[string]string // domain -> name -> value
	proxyURL string
	mu       sync.Mutex
}

func New(proxyURL string) (*Client, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_146),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithNotFollowRedirects(),
	}
	if proxyURL != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxyURL))
	}
	t, err := tls_client.NewHttpClient(nil, opts...)
	if err != nil {
		return nil, fmt.Errorf("tls-client: %w", err)
	}
	return &Client{
		tls:      t,
		cookies:  make(map[string]map[string]string),
		proxyURL: proxyURL,
	}, nil
}

func (c *Client) ProxyURL() string {
	return c.proxyURL
}

// storeCookies extracts Set-Cookie headers and stores them.
func (c *Client) storeCookies(reqURL string, resp *fhttp.Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeCookiesLocked(reqURL, resp)
}

// storeCookiesLocked is storeCookies without locking; the caller already holds c.mu.
func (c *Client) storeCookiesLocked(reqURL string, resp *fhttp.Response) {
	u, _ := url.Parse(reqURL)
	if u == nil {
		return
	}

	for _, sc := range resp.Header.Values("Set-Cookie") {
		parts := strings.Split(sc, ";")
		if len(parts) == 0 {
			continue
		}
		kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(kv) != 2 {
			continue
		}
		name, value := kv[0], kv[1]

		// Determine domain from Set-Cookie or use request host
		domain := u.Hostname()
		for _, attr := range parts[1:] {
			a := strings.TrimSpace(attr)
			if d, ok := strings.CutPrefix(strings.ToLower(a), "domain="); ok {
				d = strings.TrimPrefix(d, ".")
				if d != "" {
					domain = d
				}
			}
		}

		if c.cookies[domain] == nil {
			c.cookies[domain] = make(map[string]string)
		}
		c.cookies[domain][name] = value
	}
}

// cookieHeader builds the Cookie header for a given URL.
func (c *Client) cookieHeader(rawURL string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cookieHeaderLocked(rawURL)
}

// cookieHeaderLocked is cookieHeader without locking; caller holds c.mu.
func (c *Client) cookieHeaderLocked(rawURL string) string {
	u, _ := url.Parse(rawURL)
	if u == nil {
		return ""
	}
	host := u.Hostname()

	var pairs []string
	for domain, cookies := range c.cookies {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			for name, value := range cookies {
				pairs = append(pairs, name+"="+value)
			}
		}
	}
	return strings.Join(pairs, "; ")
}

// GetCookieValue returns a specific cookie value.
func (c *Client) GetCookieValue(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cookies := range c.cookies {
		if v, ok := cookies[name]; ok {
			return v
		}
	}
	return ""
}

func (c *Client) SetCookie(rawURL, name, value string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	domain := u.Hostname()
	if c.cookies[domain] == nil {
		c.cookies[domain] = make(map[string]string)
	}
	c.cookies[domain][name] = value
}

// exec runs a fhttp request, stores cookies, returns standard http.Response.
//
// The whole request, including SetFollowRedirect, runs under c.mu so that
// concurrent Do()/DoNoRedirect() calls cannot race on the client-wide redirect
// flag. This CLI issues sequential requests, so serializing is cheap and
// preserves behavior without forcing a second tls-client instance per
// redirect policy.
func (c *Client) exec(req *fhttp.Request, followRedirects bool) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Set default browser headers if not present
	setIfEmpty := func(k, v string) {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	setIfEmpty("User-Agent", UA)
	setIfEmpty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	setIfEmpty("Accept-Language", "zh-CN,zh;q=0.9")
	setIfEmpty("Accept-Encoding", "gzip, deflate, br")
	setIfEmpty("Sec-Ch-Ua", `"Google Chrome";v="146", "Not.A/Brand";v="8", "Chromium";v="146"`)
	setIfEmpty("Sec-Ch-Ua-Mobile", "?0")
	setIfEmpty("Sec-Ch-Ua-Platform", `"Windows"`)

	// Inject stored cookies inside the same lock used for storeCookies so
	// read-modify-write on the cookie map stays in one critical section.
	ck := c.cookieHeaderLocked(req.URL.String())
	if ck != "" {
		existing := req.Header.Get("Cookie")
		if existing != "" {
			req.Header.Set("Cookie", existing+"; "+ck)
		} else {
			req.Header.Set("Cookie", ck)
		}
	}

	c.tls.SetFollowRedirect(followRedirects)
	resp, err := c.tls.Do(req)
	if err != nil {
		return nil, err
	}

	c.storeCookiesLocked(req.URL.String(), resp)

	// Convert to standard http.Response
	h := make(http.Header)
	maps.Copy(h, resp.Header)
	return &http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Header:     h,
		Body:       resp.Body,
		Request:    &http.Request{URL: req.URL},
	}, nil
}

func (c *Client) GetNoRedirect(rawURL string) (*http.Response, error) {
	req, err := fhttp.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build get request: %w", err)
	}
	req.Header.Set("User-Agent", UA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="146", "Not.A/Brand";v="8", "Chromium";v="146"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	return c.exec(req, false)
}

func (c *Client) Do(stdReq *http.Request) (*http.Response, error) {
	return c.doStd(stdReq, true)
}

func (c *Client) DoNoRedirect(stdReq *http.Request) (*http.Response, error) {
	return c.doStd(stdReq, false)
}

func (c *Client) doStd(stdReq *http.Request, followRedirects bool) (*http.Response, error) {
	var buf []byte
	if stdReq.Body != nil {
		var err error
		buf, err = io.ReadAll(stdReq.Body)
		if cerr := stdReq.Body.Close(); cerr != nil {
			if err == nil {
				err = fmt.Errorf("close request body: %w", cerr)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}
	req, err := fhttp.NewRequest(stdReq.Method, stdReq.URL.String(), bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build fhttp request: %w", err)
	}
	for k, vs := range stdReq.Header {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	return c.exec(req, followRedirects)
}
