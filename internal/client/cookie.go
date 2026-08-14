package client

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	HTTPOnly bool
	Secure   bool
	SameSite string
	Expires  *time.Time
}

func (c *Client) storeCookiesLocked(rawURL string, response *fhttp.Response) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	for _, header := range response.Header.Values("Set-Cookie") {
		cookie, ok := parseCookie(u.Hostname(), header)
		if !ok {
			continue
		}
		c.storeCookieLocked(cookie)
	}
}

func parseCookie(host, header string) (Cookie, bool) {
	parts := strings.Split(header, ";")
	if len(parts) == 0 {
		return Cookie{}, false
	}
	name, value, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
	if !ok || name == "" {
		return Cookie{}, false
	}
	cookie := Cookie{Name: name, Value: value, Domain: host, Path: "/"}
	for _, attribute := range parts[1:] {
		attribute = strings.TrimSpace(attribute)
		lower := strings.ToLower(attribute)
		switch {
		case lower == "httponly":
			cookie.HTTPOnly = true
		case lower == "secure":
			cookie.Secure = true
		case strings.HasPrefix(lower, "domain="):
			cookie.Domain = strings.TrimPrefix(strings.TrimSpace(attribute[len("domain="):]), ".")
		case strings.HasPrefix(lower, "path="):
			cookie.Path = strings.TrimSpace(attribute[len("path="):])
		case strings.HasPrefix(lower, "samesite="):
			cookie.SameSite = strings.TrimSpace(attribute[len("samesite="):])
		case strings.HasPrefix(lower, "expires="):
			expires, err := http.ParseTime(strings.TrimSpace(attribute[len("expires="):]))
			if err == nil {
				cookie.Expires = &expires
			}
		}
	}
	return cookie, cookie.Domain != ""
}

func (c *Client) SetCookie(rawURL, name, value string) {
	c.StoreCookie(rawURL, Cookie{Name: name, Value: value})
}

func (c *Client) StoreCookie(rawURL string, cookie Cookie) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	if cookie.Domain == "" {
		cookie.Domain = u.Hostname()
	}
	cookie.Domain = strings.TrimPrefix(cookie.Domain, ".")
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeCookieLocked(cookie)
}

func (c *Client) storeCookieLocked(cookie Cookie) {
	if c.cookies[cookie.Domain] == nil {
		c.cookies[cookie.Domain] = make(map[string]Cookie)
	}
	c.cookies[cookie.Domain][cookie.Name] = cookie
}

func (c *Client) GetCookieValue(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cookies := range c.cookies {
		if cookie, ok := cookies[name]; ok {
			return cookie.Value
		}
	}
	return ""
}

func (c *Client) CookiesForURL(rawURL string) []Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cookiesForURLLocked(u)
}

func (c *Client) cookieHeaderLocked(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	cookies := c.cookiesForURLLocked(u)
	pairs := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		pairs = append(pairs, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(pairs, "; ")
}

func (c *Client) cookiesForURLLocked(u *url.URL) []Cookie {
	var matches []Cookie
	for domain, cookies := range c.cookies {
		if u.Hostname() != domain && !strings.HasSuffix(u.Hostname(), "."+domain) {
			continue
		}
		for _, cookie := range cookies {
			if cookie.Secure && u.Scheme != "https" {
				continue
			}
			if !strings.HasPrefix(u.EscapedPath(), cookie.Path) {
				continue
			}
			matches = append(matches, cookie)
		}
	}
	return matches
}
