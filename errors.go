package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/pardot/oidc/oauth2"
	xoauth2 "golang.org/x/oauth2"
)

// HTTPError indicates a generic HTTP error occured during an interaction. It
// exposes details about the returned response, as well as the original error
type HTTPError struct {
	Response *http.Response
	Body     []byte
	Cause    error
}

func (h *HTTPError) Error() string {
	return fmt.Sprintf("http status %s: %s", h.Response.Status, string(h.Body))
}

func (h *HTTPError) Unwrap() error {
	return h.Cause
}

// parseTokenError takes an error returned from the oauth2.Exchange method, and
// returns the first match of:
// * an oauth2.TokenError if the response was 400 or 401, and contains a
// correctly formatted response in the body
// * a HttpError if a general HTTP error response was returned
// * A generic error for all other errors
func parseExchangeError(err error) error {
	var rerr *xoauth2.RetrieveError
	if errors.As(err, &rerr) {
		// set this up as the default case if we can't handle the error more intelligently
		herr := HTTPError{
			Response: rerr.Response,
			Body:     rerr.Body,
			// ignore cause to not make x/oauth2 part of the contract
		}

		if rerr.Response.StatusCode == 400 || rerr.Response.StatusCode == 401 {
			// this should be a token error. Try and parse, else fall back to a http error
			terr := oauth2.TokenError{}
			if err := json.Unmarshal(rerr.Body, &terr); err != nil {
				// not formatted correctly/non-standard, treat as HTTP
				return &herr
			}
			terr.WWWAuthenticate = rerr.Response.Header.Get("www-authenticate")
			return &terr
		}
		return &herr
	}
	return fmt.Errorf("error exchanging token: %v", err)
}
