package core

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type responseType string

const (
	responseTypeCode     responseType = "code"
	responseTypeImplicit responseType = "token"
)

type authRequest struct {
	ClientID string
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value
	RedirectURI  string
	State        string
	Scopes       []string
	ResponseType responseType
}

// parseAuthRequest can be used to process an oauth2 authentication request,
// returning information about it. It can handle both the code and implicit auth
// types. If an error is returned, it should be passed to the user via
// writeError
//
// https://tools.ietf.org/html/rfc6749#section-4.1.1
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func parseAuthRequest(req *http.Request) (authReq *authRequest, err error) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return nil, &httpError{Code: http.StatusBadRequest, Message: "method must be POST or GET"}
	}

	if err := req.ParseForm(); err != nil {
		return nil, &httpError{Code: http.StatusBadRequest, Message: "failed to parse request", Cause: err}
	}

	rts := req.FormValue("response_type")
	cid := req.FormValue("client_id")
	ruri := req.FormValue("redirect_uri")
	scope := req.FormValue("scope")
	state := req.FormValue("state")

	var rt responseType
	switch rts {
	case string(responseTypeCode):
		rt = responseTypeCode
	case string(responseTypeImplicit):
		rt = responseTypeImplicit
	default:
		return nil, &authError{
			State:       state,
			Code:        authErrorCodeInvalidRequest,
			Description: `response_type must be "code" or "token"`,
			RedirectURI: ruri,
		}
	}

	if cid == "" {
		return nil, &authError{
			State:       state,
			Code:        authErrorCodeInvalidRequest,
			Description: "client_id must be specified",
			RedirectURI: ruri,
		}
	}

	return &authRequest{
		ClientID:     cid,
		RedirectURI:  ruri,
		State:        state,
		Scopes:       strings.Split(strings.TrimSpace(scope), " "),
		ResponseType: rt,
	}, nil
}

type codeAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Code        string
}

// sendCodeAuthResponse sends the appropriate response to an auth request of
// response_type code, aka "Code flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2
func sendCodeAuthResponse(w http.ResponseWriter, req *http.Request, resp *codeAuthResponse) {
	redir := authResponse(resp.RedirectURI, resp.State)
	v := redir.Query()
	v.Add("code", resp.Code)
	redir.RawQuery = v.Encode()
	http.Redirect(w, req, redir.String(), http.StatusFound)
}

type tokenType string

const ( // https://tools.ietf.org/html/rfc6749#section-7.1 , https://tools.ietf.org/html/rfc6750
	tokenTypeBearer tokenType = "Bearer"
)

type tokenAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Token       string
	TokenType   tokenType
	Scopes      []string
	ExpiresIn   time.Duration
}

// sendTokenAuthResponse sends the appropriate response to an auth request of
// response_type token, aka "Implicit flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.2.2
func sendTokenAuthResponse(w http.ResponseWriter, req *http.Request, resp *tokenAuthResponse) {
	redir := authResponse(resp.RedirectURI, resp.State)
	v := redir.Query()
	v.Add("access_token", resp.Token)
	v.Add("token_type", string(resp.TokenType))
	if resp.ExpiresIn != 0 {
		v.Add("expires_in", fmt.Sprintf("%d", int(resp.ExpiresIn.Seconds())))
	}
	if resp.Scopes != nil {
		v.Add("scope", strings.Join(resp.Scopes, " "))
	}
	redir.RawQuery = v.Encode()
	http.Redirect(w, req, redir.String(), http.StatusFound)
}

func authResponse(redir *url.URL, state string) *url.URL {
	v := redir.Query()
	if state != "" {
		v.Add("state", state)
	}
	redir.RawQuery = v.Encode()
	return redir
}
