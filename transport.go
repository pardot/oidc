package oidc

import (
	"errors"
	"net/http"
)

var _ http.RoundTripper = (*Transport)(nil)

type Transport struct {
	TokenSource

	// Base is the base RoundTripper to make HTTP requests. If nil,
	// http.DefaultTransport is used.
	Base http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// RoundTrip must always close the body, including on errors,
	// but depending on the implementation may do so in a separate
	// goroutine even after RoundTrip returns. This means that
	// callers wanting to reuse the body for subsequent requests
	// must arrange to wait for the Close call before doing so.
	bodyClosed := false
	if req.Body != nil {
		defer func() {
			if !bodyClosed {
				req.Body.Close()
			}
		}()
	}

	if t.TokenSource == nil {
		return nil, errors.New("missing TokenSource")
	}

	token, err := t.Token(req.Context())
	if err != nil {
		return nil, err
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	// RoundTrip should not modify the request, except for
	// consuming and closing the Request's Body. RoundTrip may
	// read fields of the request in a separate goroutine. Callers
	// should not mutate or reuse the request until the Response's
	// Body has been closed.
	req2 := cloneRequest(req)
	req2.Header.Set("authorization", token.Type()+" "+token.IDToken)

	res, err := base.RoundTrip(req2)
	// The base transporter will have closed the body by this point
	bodyClosed = true

	return res, err
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy
	r2 := new(http.Request)
	*r2 = *r

	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, v := range r.Header {
		r2.Header[k] = append([]string(nil), v...)
	}

	return r2
}
