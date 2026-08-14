package client

import "net/http"

type AuthDirect func(*http.Request, bool) (*http.Response, error)

type AuthTransport interface {
	HandleAuthRequest(*http.Request, bool, AuthDirect) (*http.Response, error)
}
