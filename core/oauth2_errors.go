package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pardot/oidc/oauth2"
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
		if err.WWWAuthenticate != "" {
			w.Header().Add("WWW-Authenticate", err.WWWAuthenticate)
		}
		code := err.Code
		if code == 0 {
			code = http.StatusInternalServerError
		}
		http.Error(w, m, code)

	case *oauth2.TokenError:
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		// https://tools.ietf.org/html/rfc6749#section-5.2
		if err.ErrorCode == oauth2.TokenErrorCodeInvalidClient {
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
	// WWWAuthenticate is passed in the appropriate header field in the response
	WWWAuthenticate string
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

type bearerErrorCode string

// https://tools.ietf.org/html/rfc6750#section-3.1
// nolint:unused,varcheck,deadcode
const (
	// The request is missing a required parameter, includes an unsupported
	// parameter or parameter value, repeats the same parameter, uses more than
	// one method for including an access token, or is otherwise malformed.  The
	// resource server SHOULD respond with the HTTP 400 (Bad Request) status
	// code.
	bearerErrorCodeInvalidRequest bearerErrorCode = "invalid_request"
	// The access token provided is expired, revoked, malformed, or invalid for
	// other reasons.  The resource SHOULD respond with the HTTP 401
	// (Unauthorized) status code.  The client MAY request a new access token
	// and retry the protected resource request.
	bearerErrorCodeInvalidToken bearerErrorCode = "invalid_token"
	// The request requires higher privileges than provided by the access token.
	// The resource server SHOULD respond with the HTTP 403 (Forbidden) status
	// code and MAY include the "scope" attribute with the scope necessary to
	// access the protected resource.
	bearerErrorCodeInsufficientScope bearerErrorCode = "insufficient_scope"
)

// bearerError represents the contents that can be returned in the
// www-authenticate header for requests failing to auth under oauth2 bearer
// token usage
//
// https://tools.ietf.org/html/rfc6750#section-3
type bearerError struct {
	Realm       string
	Code        bearerErrorCode
	Description string
}

// String encodes the error in a format suitible for including in a www-authenticate header
func (b *bearerError) String() string {
	ret := []string{}
	if b.Realm != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "realm", b.Realm))
	}
	if b.Code != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "error", b.Code))
	}
	if b.Description != "" {
		ret = append(ret, fmt.Sprintf("%s=%q", "error_description", b.Description))
	}
	return "Bearer " + strings.Join(ret, " ")
}
