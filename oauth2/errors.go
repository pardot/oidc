package oauth2

import "fmt"

// TokenErrorCode are the types of error that can be returned
type TokenErrorCode string

// https://tools.ietf.org/html/rfc6749#section-5.2
// nolint:unused
const (
	// TokenErrorCodeInvalidRequest: The request is missing a required
	// parameter, includes an unsupported parameter value (other than grant
	// type), repeats a parameter, includes multiple credentials, utilizes more
	// than one mechanism for authenticating the client, or is otherwise
	// malformed.
	TokenErrorCodeInvalidRequest TokenErrorCode = "invalid_request"
	// TokenErrorCodeInvalidClient: Client authentication failed (e.g., unknown
	// client, no client authentication included, or unsupported authentication
	// method).  The authorization server MAY return an HTTP 401 (Unauthorized)
	// status code to indicate which HTTP authentication schemes are supported.
	// If the client attempted to authenticate via the "Authorization" request
	// header field, the authorization server MUST respond with an HTTP 401
	// (Unauthorized) status code and include the "WWW-Authenticate" response
	// header field matching the authentication scheme used by the client.
	TokenErrorCodeInvalidClient TokenErrorCode = "invalid_client"
	// TokenErrorCodeInvalidGrant: The provided authorization grant (e.g.,
	// authorization code, resource owner credentials) or refresh token is
	// invalid, expired, revoked, does not match the redirection URI used in the
	// authorization request, or was issued to another client.
	TokenErrorCodeInvalidGrant TokenErrorCode = "invalid_grant"
	// TokenErrorCodeUnauthorizedClient: The authenticated client is not
	// authorized to use this authorization grant type.
	TokenErrorCodeUnauthorizedClient TokenErrorCode = "unauthorized_client"
	// TokenErrorCodeUnsupportedGrantType: The authorization grant type is not
	// supported by the authorization server.
	TokenErrorCodeUnsupportedGrantType TokenErrorCode = "unsupported_grant_type"
	// TokenErrorCodeInvalidScope: The requested scope is invalid, unknown,
	// malformed, or exceeds the scope granted by the resource owner.
	TokenErrorCodeInvalidScope TokenErrorCode = "invalid_scope"
)

// TokenError represents an error returned from calling the token endpoint.
//
// https://tools.ietf.org/html/rfc6749#section-5.2
type TokenError struct {
	// ErrorCode indicates the type of error that occurred
	ErrorCode TokenErrorCode `json:"error,omitempty"`
	// Description: OPTIONAL.  Human-readable ASCII [USASCII] text providing
	// additional information, used to assist the client developer in
	// understanding the error that occurred. Values for the "error_description"
	// parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
	// %x5D-7E.
	Description string `json:"error_description,omitempty"`
	// ErrorURI: OPTIONAL.  A URI identifying a human-readable web page with
	// information about the error, used to provide the client developer with
	// additional information about the error. Values for the "error_uri"
	// parameter MUST conform to the URI-reference syntax and thus MUST NOT
	// include characters outside the set %x21 / %x23-5B / %x5D-7E.
	ErrorURI string `json:"error_uri,omitempty"`
	// 	WWWAuthenticate is set when an invalid_client error is returned, and
	// 	that response indicates the authentication scheme to be used by the
	// 	client
	WWWAuthenticate string `json:"-"`
	// Cause wraps any upstream error that resulted in this token being issued,
	// if this error should be unrwappable
	Cause error `json:"-"`
}

// Error returns a string representing this error
func (t *TokenError) Error() string {
	str := fmt.Sprintf("%s error in token request: %s", t.ErrorCode, t.Description)
	if t.Cause != nil {
		str = fmt.Sprintf("%s (cause: %s)", str, t.Cause.Error())
	}
	return str
}

func (t *TokenError) Unwrap() error {
	return t.Cause
}
