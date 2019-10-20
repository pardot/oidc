package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// writeError handles the passed error appropriately. After calling this, the
// HTTP sequence should be considered complete.
//
// For errors in the authorization endpoint, the user will be redirected with
// the code appended to the redirect URL.
// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
//
// For unknown errors, an InternalServerError response will be sent
func writeError(w http.ResponseWriter, req *http.Request, err error) error {
	switch err := err.(type) {
	case *authError:
		redir, perr := url.Parse(err.RedirectURI)
		if perr != nil {
			return fmt.Errorf("failed to parse redirect URI %q: %w", err.RedirectURI, perr)
		}
		v := redir.Query()
		if err.State != "" {
			v.Add("state", err.State)
		}
		v.Add("error", string(err.Code))
		if err.Description != "" {
			v.Add("error_description", err.Description)
		}
		redir.RawQuery = v.Encode()
		http.Redirect(w, req, redir.String(), http.StatusFound)

	case *httpError:
		m := err.Message
		if m == "" {
			m = "Internal error"
		}
		http.Error(w, m, err.Code)

	case *tokenError:
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		// https://tools.ietf.org/html/rfc6749#section-5.2
		if err.Code == tokenErrorCodeInvalidClient {
			if err.WWWAuthenticate != "" {
				w.Header().Add("WWW-Authenticate", err.WWWAuthenticate)
			}
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		if err := json.NewEncoder(w).Encode(err); err != nil {
			return fmt.Errorf("failed to write token error json body: %w", err)
		}

	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	return nil
}

type httpError struct {
	Code int
	// Message is presented to the user, so this should be considered.
	// if it's not set, "Internal error" will be used.
	Message string
	// cause message is presented in the Error() output, so it should be used
	// for internal text
	CauseMsg string
	Cause    error
}

func (h *httpError) Error() string {
	m := h.CauseMsg
	if m == "" {
		m = h.Message
	}
	str := fmt.Sprintf("http error %d: %s", h.Code, m)
	if h.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, h.Cause.Error())
	}
	return str
}

func (h *httpError) Unwrap() error {
	return h.Cause
}

// writeAuthError will build and send an httpErr for this HTTP response cycle,
// returning the error that was written. It will ignore any errors actually
// writing the error to the user.
func writeHTTPError(w http.ResponseWriter, req *http.Request, code int, message string, cause error, causeMsg string) error {
	err := &httpError{
		Code:     code,
		Message:  message,
		Cause:    cause,
		CauseMsg: causeMsg,
	}
	_ = writeError(w, req, err)
	return err
}

type authErrorCode string

// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
// nolint:unused,varcheck,deadcode
const (
	authErrorCodeInvalidRequest           authErrorCode = "invalid_request"
	authErrorCodeUnauthorizedClient       authErrorCode = "unauthorized_client"
	authErrorCodeAccessDenied             authErrorCode = "access_denied"
	authErrorCodeUnsupportedResponseType  authErrorCode = "unsupported_response_type"
	authErrorCodeInvalidScope             authErrorCode = "invalid_scope"
	authErrorCodeErrServerError           authErrorCode = "server_error"
	authErrorCodeErrTemporarilyUnvailable authErrorCode = "temporarily_unavailable"
)

type authError struct {
	State       string
	Code        authErrorCode
	Description string
	RedirectURI string
	Cause       error
}

func (a *authError) Error() string {
	str := fmt.Sprintf("%s error in authorization request: %s", a.Code, a.Description)
	if a.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, a.Cause.Error())
	}
	return str
}

func (a *authError) Unwrap() error {
	return a.Cause
}

// writeAuthError will build and send an authError for this HTTP response cycle,
// returning the error that was written. It will ignore any errors actually
// writing the error to the user.
func writeAuthError(w http.ResponseWriter, req *http.Request, redirectURI *url.URL, code authErrorCode, state, description string, cause error) error {
	err := &authError{
		State:       state,
		Code:        code,
		Description: description,
		RedirectURI: redirectURI.String(),
		Cause:       cause,
	}
	_ = writeError(w, req, err)
	return err
}

// addRedirectToError can attach a redirect URI to an error. This is uncommon,
// but useful when the redirect URI is configured at the client only, and not
// passed in the authorization request. If the error cannot make use of this, it
// will be ignored and the original error returned
func addRedirectToError(err error, redirectURI string) error { //nolint:unparam,unused,deadcode
	if err, ok := err.(*authError); ok {
		err.RedirectURI = redirectURI
		return err
	}
	return err
}

type tokenErrorCode string

// https://tools.ietf.org/html/rfc6749#section-5.2
// nolint:unused,varcheck,deadcode
const (
	tokenErrorCodeInvalidRequest       tokenErrorCode = "invalid_request"
	tokenErrorCodeInvalidClient        tokenErrorCode = "invalid_client"
	tokenErrorCodeInvalidGrant         tokenErrorCode = "invalid_grant"
	tokenErrorCodeUnauthorizedClient   tokenErrorCode = "unauthorized_client"
	tokenErrorCodeUnsupportedGrantType tokenErrorCode = "unsupported_grant_type"
	tokenErrorCodeInvalidScope         tokenErrorCode = "invalid_scope"
)

type tokenError struct {
	Code            tokenErrorCode `json:"error,omitempty"`
	Description     string         `json:"error_description,omitempty"`
	ErrorURI        string         `json:"error_uri,omitempty"`
	Cause           error          `json:"-"`
	WWWAuthenticate string         `json:"-"`
}

func (t *tokenError) Error() string {
	return fmt.Sprintf("%s error in authorization request: %s", t.Code, t.Description)
}

func (t *tokenError) Unwrap() error {
	return t.Cause
}
