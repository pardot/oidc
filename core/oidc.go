package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pardot/oidc"
	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
	"gopkg.in/square/go-jose.v2"
)

// Session represents an invidual user session, bound to a given client.
//
// The Session object is serializable as a protobuf Message both in the binary
// and JSON formats.
type Session interface {
	proto.Message
	// GetId returns the unique identifier for tracking this session.
	GetId() string
	// GetExpiresAt returns the time this session expires. Implementations
	// should garbage collect expired sessions, as this implementation doesn't
	GetExpiresAt() *timestamp.Timestamp
}

// SessionManager is used to track the state of the session across it's
// lifecycle.
type SessionManager interface {
	// NewID should return a new, unique identifier to be used for a session. It
	// should be hard to guess/brute force
	NewID() string
	// GetSession should return the current session state for the given session
	// ID. It should be deserialized/written in to into. If the session does not
	// exist, found should be false with no error.
	GetSession(ctx context.Context, sessionID string, into Session) (found bool, err error)
	// PutSession should persist the new state of the session
	PutSession(context.Context, Session) error
	// DeleteSession should remove the corresponding session.
	DeleteSession(ctx context.Context, sessionID string) error
}

// Signer is used for signing identity tokens
type Signer interface {
	// SignerAlg returns the algorithm the signer uses
	SignerAlg(ctx context.Context) (jose.SignatureAlgorithm, error)
	// Sign the provided data
	Sign(ctx context.Context, data []byte) (signed []byte, err error)
	// VerifySignature verifies the signature given token against the current signers
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

// ClientSource is used for validating client informantion for the general flow
type ClientSource interface {
	// IsValidClientID should return true if the passed client ID is valid
	IsValidClientID(clientID string) (ok bool, err error)
	// IsUnauthenticatedClient is used to check if the client should be required
	// to pass a client secret. If not, this will not be checked
	IsUnauthenticatedClient(clientID string) (ok bool, err error)
	// ValidateClientSecret should confirm if the passed secret is valid for the
	// given client
	ValidateClientSecret(clientID, clientSecret string) (ok bool, err error)
	// ValidateRedirectURI should confirm if the given redirect is valid for the client. It should
	// compare as per https://tools.ietf.org/html/rfc3986#section-6
	ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error)
}

const (
	// DefaultAuthValidityTime is used if the AuthValidityTime is not
	// configured.
	DefaultAuthValidityTime = 1 * time.Hour
	// DefaultCodeValidityTime is used if the CodeValidityTime is not
	// configured.
	DefaultCodeValidityTime = 60 * time.Second
)

// Config sets configuration values for the OIDC flow implementation
type Config struct {
	// AuthValidityTime is the maximum time an authorization flow/AuthID is
	// valid. This is the time from Starting to Finishing the authorization. The
	// optimal time here will be application specific, and should encompass how
	// long the app expects a user to complete the "upstream" authorization
	// process.
	AuthValidityTime time.Duration
	// CodeValidityTime is the maximum time the authorization code is valid,
	// before it is exchanged for a token (code flow). This should be a short
	// value, as the exhange should generally not take long
	CodeValidityTime time.Duration
}

// OIDC can be used to handle the various parts of the OIDC auth flow.
type OIDC struct {
	smgr    SessionManager
	clients ClientSource
	signer  Signer

	authValidityTime time.Duration
	codeValidityTime time.Duration

	now   func() time.Time
	tsnow func() *timestamp.Timestamp
}

func New(cfg *Config, smgr SessionManager, clientSource ClientSource, signer Signer) (*OIDC, error) {
	o := &OIDC{
		smgr:    smgr,
		clients: clientSource,
		signer:  signer,

		authValidityTime: cfg.AuthValidityTime,
		codeValidityTime: cfg.CodeValidityTime,

		now:   time.Now,
		tsnow: ptypes.TimestampNow,
	}

	if o.authValidityTime == time.Duration(0) {
		o.authValidityTime = DefaultAuthValidityTime
	}
	if o.codeValidityTime == time.Duration(0) {
		o.codeValidityTime = DefaultCodeValidityTime
	}

	return o, nil
}

// AuthorizationRequest details the information the user starting the
// authorization flow requested
type AuthorizationRequest struct {
	// SessionID that was generated for this session. This should be tracked
	// throughout the authentication process
	SessionID string
	// ACRValues are the authentication context class reference values the
	// caller requested
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
	ACRValues []string
	// Scopes that have been requested
	Scopes []string
	// ClientID that started this request
	ClientID string
}

// StartAuthorization can be used to handle a request to the auth endpoint. It
// will parse and validate the incoming request, returning a unique identifier.
// If an error was returned, it should be assumed that this has been returned to
// the user appropriately. Otherwise, no response will be written. The caller
// can then use this request to implement the appropriate auth flow. The authID
// should be kept and treated as sensitive - it will be used to mark the request
// as Authorized.
//
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
func (o *OIDC) StartAuthorization(w http.ResponseWriter, req *http.Request) (*AuthorizationRequest, error) {
	authreq, err := parseAuthRequest(req)
	if err != nil {
		_ = writeError(w, req, err)
		return nil, fmt.Errorf("failed to parse auth endpoint request: %w", err)
	}

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		return nil, writeHTTPError(w, req, http.StatusInternalServerError, "redirect_uri is in an invalid format", err, "failed to parse redirect URI")
	}

	// If a non valid client ID or redirect URI is specified, we should return
	// an error directly to the user rather than passing it on the redirect.
	//
	// https://tools.ietf.org/html/rfc6749#section-4.1.2.1

	cidok, err := o.clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		return nil, writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource check client ID")
	}
	if !cidok {
		return nil, writeHTTPError(w, req, http.StatusBadRequest, "Client ID is not valid", nil, "")
	}

	redirok, err := o.clients.ValidateClientRedirectURI(authreq.ClientID, authreq.RedirectURI)
	if err != nil {
		return nil, writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource redirect URI validation")
	}
	if !redirok {
		return nil, writeHTTPError(w, req, http.StatusBadRequest, "Invalid redirect URI", nil, "")
	}

	ar := &corev1beta1.AuthRequest{
		RedirectUri: redir.String(),
		State:       authreq.State,
		Scopes:      authreq.Scopes,
		Nonce:       authreq.Raw.Get("nonce"),
	}

	switch authreq.ResponseType {
	case responseTypeCode:
		ar.ResponseType = corev1beta1.AuthRequest_CODE
	default:
		return nil, writeAuthError(w, req, redir, authErrorCodeUnsupportedResponseType, authreq.State, "response type must be code", nil)
	}

	sess := &corev1beta1.Session{
		Id:        o.smgr.NewID(),
		Stage:     corev1beta1.Session_REQUESTED,
		ClientId:  authreq.ClientID,
		Request:   ar,
		ExpiresAt: tsAdd(o.tsnow(), o.authValidityTime),
	}

	if err := o.smgr.PutSession(req.Context(), sess); err != nil {
		return nil, writeAuthError(w, req, redir, authErrorCodeErrServerError, authreq.State, "failed to persist session", err)
	}

	areq := &AuthorizationRequest{
		SessionID: sess.Id,
		Scopes:    authreq.Scopes,
		ClientID:  authreq.ClientID,
	}
	if authreq.Raw.Get("acr_values") != "" {
		areq.ACRValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}
	return areq, nil
}

// Authorization tracks the information a session was actually authorized for
type Authorization struct {
	// Scopes are the list of scopes this session was granted
	Scopes []string
	// ACR is the Authentication Context Class Reference the session was
	// authenticated with
	ACR string
	// AMR are the Authentication Methods Reference the session was
	// authenticated with
	AMR []string
}

// FinishAuthorization should be called once the consumer has validated the
// identity of the user. This will return the appropriate response directly to
// the passed http context, which should be considered finalized when this is
// called. Note: This does not have to be the same http request in which
// Authorization was started, but the session ID field will need to be tracked and
// consistent.
//
// The scopes this request has been granted with should be included. Metadata
// can be passed, that will be made available to requests to userinfo and token
// issue/refresh. This is application-specific, and should be used to track
// information needed to serve those endpoints.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (o *OIDC) FinishAuthorization(w http.ResponseWriter, req *http.Request, sessionID string, auth *Authorization) error {
	sess, err := getSession(req.Context(), o.smgr, sessionID)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get session")
	}
	if sess == nil {
		return writeHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "session not found in storage")
	}

	var openidScope bool
	for _, s := range auth.Scopes {
		if s == "openid" {
			openidScope = true
		}
	}
	if !openidScope {
		return writeHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "openid scope was not granted")

	}

	sess.Authorization = &corev1beta1.Authorization{
		Scopes:       auth.Scopes,
		Acr:          auth.ACR,
		Amr:          auth.AMR,
		AuthorizedAt: o.tsnow(),
	}

	switch sess.Request.ResponseType {
	case corev1beta1.AuthRequest_CODE:
		return o.finishCodeAuthorization(w, req, sess)
	default:
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", sess.Request.ResponseType.String()))
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, session *corev1beta1.Session) error {
	codeExp := tsAdd(o.tsnow(), o.codeValidityTime)

	ucode, scode, err := newToken(session.Id, codeExp)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to generate code token")
	}

	code, err := marshalToken(ucode)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal code token")
	}

	session.AuthCode = scode
	session.Stage = corev1beta1.Session_CODE
	// switch expiry to the max lifetime of the code
	session.ExpiresAt = codeExp

	if err := o.smgr.PutSession(req.Context(), session); err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to put authReq to storage")
	}

	redir, err := url.Parse(session.Request.RedirectUri)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to parse authreq's URI")
	}

	codeResp := &codeAuthResponse{
		RedirectURI: redir,
		State:       session.Request.State,
		Code:        code,
	}

	sendCodeAuthResponse(w, req, codeResp)

	return nil
}

// TokenRequest encapsulates the information from the request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// SessionID of the session this request corresponds to
	SessionID string
	// ClientID of the client this session is bound to.
	ClientID string
	// Authorization information this session was authorized with
	Authorization Authorization
	// GrantType indicates the grant that was requested for this invocation of
	// the token endpoint
	GrantType GrantType
	// SessionRefreshable is true if the offline_access scope was permitted for
	// the user, i.e this session should issue refresh tokens
	SessionRefreshable bool
	// IsRefresh is true if the token endpoint was called with the refresh token
	// grant (i.e called with a refresh, rather than access token)
	IsRefresh bool

	authTime *timestamp.Timestamp
	authReq  *corev1beta1.AuthRequest
	now      func() time.Time
}

// PrefillIDToken can be used to create a basic ID token containing all required
// claims, mapped with information from this request. The issuer and subject
// will be set as provided, and the token's expiry will be set to the
// appropriate time base on the validity period
//
// Aside from the explicitly passed fields, the following information will be set:
// * Audience (aud) will contain the Client ID
// * ACR claim set
// * AMR claim set
// * Issued At (iat) time set
// * Auth Time (auth_time) time set
// * Nonce that was originally passed in, if there was one
func (t *TokenRequest) PrefillIDToken(iss, sub string, expires time.Time) oidc.Claims {
	return oidc.Claims{
		Issuer:   iss,
		Subject:  sub,
		Expiry:   oidc.NewUnixTime(expires),
		Audience: oidc.Audience{t.ClientID},
		ACR:      t.Authorization.ACR,
		AMR:      t.Authorization.AMR,
		IssuedAt: oidc.NewUnixTime(t.now()),
		AuthTime: newUnixTimeProto(t.authTime),
		Nonce:    t.authReq.Nonce,
		Extra:    map[string]interface{}{},
	}
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// IssueRefreshToken indicates if we should issue a refresh token.
	IssueRefreshToken bool

	// IDToken is returned as the id_token for the request to this endpoint. It
	// is up to the application to store _all_ the desired information in the
	// token correctly, and to obey the OIDC spec. The handler will make no
	// changes to this token.
	IDToken oidc.Claims

	// AccessTokenValidUntil indicates how long the returned authorization token
	// should be valid for.
	AccessTokenValidUntil time.Time
	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, assuming one is issued.
	RefreshTokenValidUntil time.Time
}

// Token is used to handle the access token endpoint for code flow requests.
// This can handle both the initial access token request, as well as subsequent
// calls for refreshes.
//
// This will always return a response to the user, regardless of success or
// failure. As such, once returned the called can assume the HTTP request has
// been dealt with appropriately
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (o *OIDC) Token(w http.ResponseWriter, req *http.Request, handler func(req *TokenRequest) (*TokenResponse, error)) error {
	treq, err := parseTokenRequest(req)
	if err != nil {
		_ = writeError(w, req, err)
		return err
	}

	resp, err := o.token(req.Context(), treq, handler)
	if err != nil {
		_ = writeError(w, req, err)
		return err
	}

	if err := writeTokenResponse(w, resp); err != nil {
		_ = writeError(w, req, err)
		return err
	}

	return nil
}

func (o *OIDC) token(ctx context.Context, req *tokenRequest, handler func(req *TokenRequest) (*TokenResponse, error)) (*tokenResponse, error) {
	var sess *corev1beta1.Session
	var err error

	var isRefresh bool

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		sess, err = o.fetchCodeSession(ctx, req)
	case GrantTypeRefreshToken:
		isRefresh = true
		sess, err = o.fetchRefreshSession(ctx, req)

	default:
		err = &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", req.GrantType)}
	}
	if err != nil {
		return nil, err
	}

	exp, _ := ptypes.Timestamp(sess.ExpiresAt)
	if o.now().After(exp) {
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	// check to see if we're working with the same client
	if sess.ClientId != req.ClientID {
		return nil, &tokenError{Code: tokenErrorCodeUnauthorizedClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}

	// validate the client
	cok, err := o.clients.ValidateClientSecret(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check client id & secret", Cause: err}

	}
	if !cok {
		return nil, &tokenError{Code: tokenErrorCodeUnauthorizedClient, Description: "Invalid client secret"}
	}

	// Call the handler with information about the request, and get the response.
	if sess.Authorization == nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "session authorization is nil"}
	}

	tr := &TokenRequest{
		SessionID: sess.Id,
		ClientID:  req.ClientID,
		Authorization: Authorization{
			Scopes: sess.Authorization.Scopes,
			ACR:    sess.Authorization.Acr,
			AMR:    sess.Authorization.Amr,
		},
		GrantType:          req.GrantType,
		SessionRefreshable: strsContains(sess.Authorization.Scopes, "offline_access"),
		IsRefresh:          isRefresh,

		authTime: sess.Authorization.AuthorizedAt,
		authReq:  sess.Request,
		now:      o.now,
	}

	tresp, err := handler(tr)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	if tresp.AccessTokenValidUntil.Before(o.now()) {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "access token must be valid > now"}
	}

	if tresp.IssueRefreshToken && tresp.RefreshTokenValidUntil.Before(o.now()) {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "refresh token must be valid > now"}
	}

	// create a new access token
	useratok, satok, err := newToken(sess.Id, mustTs(tresp.AccessTokenValidUntil))
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}
	}
	sess.ExpiresAt = satok.ExpiresAt
	sess.AccessToken = satok
	sess.Stage = corev1beta1.Session_ACCESS_TOKEN_ISSUED

	accessTok, err := marshalToken(useratok)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal user token", Cause: err}
	}

	// If we're allowing refresh, issue one of those too.
	// do this after, as it'll set a longer expiration on the session
	var refreshTok string
	if tresp.IssueRefreshToken {
		urefreshtok, srefreshtok, err := newToken(sess.Id, mustTs(tresp.RefreshTokenValidUntil))
		if err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}
		}
		sess.ExpiresAt = srefreshtok.ExpiresAt
		sess.RefreshToken = srefreshtok
		sess.Stage = corev1beta1.Session_REFRESHABLE

		refreshTok, err = marshalToken(urefreshtok)
		if err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal refresh token", Cause: err}
		}
	} else {
		// clear any token
		sess.RefreshToken = nil
	}

	if err := o.smgr.PutSession(ctx, sess); err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to put access token", Cause: err}
	}

	idtb, err := json.Marshal(tresp.IDToken)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal id token", Cause: err}
	}

	sidt, err := o.signer.Sign(ctx, idtb)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign id token", Cause: err}
	}

	return &tokenResponse{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    tresp.AccessTokenValidUntil.Sub(o.now()),
		ExtraParams: map[string]interface{}{
			"id_token": string(sidt),
		},
	}, nil
}

// fetchCodeSession handles loading the session for a code grant.
func (o *OIDC) fetchCodeSession(ctx context.Context, treq *tokenRequest) (*corev1beta1.Session, error) {
	ucode, err := unmarshalToken(treq.Code)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	sess, err := getSession(ctx, o.smgr, ucode.SessionId)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get session from storage", Cause: err}
	}
	if sess == nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "sesion expired"}
	}

	if sess.AuthCodeRedeemed || tsAfter(sess.AuthCode.ExpiresAt, o.tsnow()) {
		// Drop the session too, assume we're under some kind of replay.
		// https://tools.ietf.org/html/rfc6819#section-4.4.1.1
		if err := o.smgr.DeleteSession(ctx, sess.Id); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(ucode, sess.AuthCode)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok {
		// if we're passed an invalid code, assume we're under attack and drop the session
		if err := o.smgr.DeleteSession(ctx, sess.Id); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "invalid code", Cause: err}
	}

	sess.AuthCodeRedeemed = true

	return sess, nil
}

// fetchCodeSession handles loading the session for a refresh grant.
func (o *OIDC) fetchRefreshSession(ctx context.Context, treq *tokenRequest) (*corev1beta1.Session, error) {
	urefresh, err := unmarshalToken(treq.RefreshToken)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}

	sess, err := getSession(ctx, o.smgr, urefresh.SessionId)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get session from storage", Cause: err}
	}
	if sess == nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "token expired", Cause: err}
	}

	if sess.RefreshToken == nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "no refresh token issued for session"}
	}

	if tsAfter(sess.ExpiresAt, o.tsnow()) || tsAfter(sess.RefreshToken.ExpiresAt, o.tsnow()) {
		if err := o.smgr.DeleteSession(ctx, sess.Id); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(urefresh, sess.RefreshToken)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}
	if !ok {
		// if we're passed an invalid refresh token, assume we're under attack and drop the session
		if err := o.smgr.DeleteSession(ctx, sess.Id); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "invalid refresh token", Cause: err}
	}

	// Drop the current token, it's been redeemed. The caller can decide to
	// issue a new one.
	sess.RefreshToken = nil

	return sess, nil
}

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoRequest struct {
	// SessionID of the session this request is for.
	SessionID string
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// appropriate response data in JSON format to the passed writer.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (o *OIDC) Userinfo(w http.ResponseWriter, req *http.Request, handler func(w io.Writer, uireq *UserinfoRequest) error) error {
	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &bearerError{} // no content, just request auth
		herr := &httpError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = writeError(w, req, herr)
		return herr
	}

	uaccess, err := unmarshalToken(authSp[1])
	if err != nil {
		be := &bearerError{Code: bearerErrorCodeInvalidRequest, Description: "malformed token"}
		herr := &httpError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = writeError(w, req, herr)
		return herr
	}

	// make sure we have an unexpired session
	sess, err := getSession(req.Context(), o.smgr, uaccess.SessionId)
	if err != nil {
		herr := &httpError{Code: http.StatusInternalServerError, Cause: err}
		_ = writeError(w, req, herr)
		return herr
	}

	// make sure we have a valid, unexpired session and an unexpired token
	if sess == nil || tsAfter(sess.ExpiresAt, o.tsnow()) || tsAfter(sess.AccessToken.ExpiresAt, o.tsnow()) {
		be := &bearerError{Code: bearerErrorCodeInvalidToken, Description: "token no longer valid"}
		herr := &httpError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "Access token expired"}
		_ = writeError(w, req, herr)
		return herr
	}

	// and make sure the token is valid
	ok, err := tokensMatch(uaccess, sess.AccessToken)
	if err != nil {
		herr := &httpError{Code: http.StatusInternalServerError, Cause: err}
		_ = writeError(w, req, herr)
		return herr
	}
	if !ok {
		// if we're passed an invalid access token drop the whole session, might
		// be under attack
		if err := o.smgr.DeleteSession(req.Context(), sess.Id); err != nil {
			herr := &httpError{Code: http.StatusInternalServerError, Cause: err}
			_ = writeError(w, req, herr)
			return herr
		}
		be := &bearerError{Code: bearerErrorCodeInvalidToken, Description: "token not valid"}
		herr := &httpError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String()}
		_ = writeError(w, req, herr)
		return herr
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		SessionID: uaccess.SessionId,
	}

	if err := handler(w, uireq); err != nil {
		herr := &httpError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = writeError(w, req, herr)
		return herr
	}

	return nil
}

func strsContains(strs []string, s string) bool {
	for _, str := range strs {
		if str == s {
			return true
		}
	}
	return false
}

func getSession(ctx context.Context, sm SessionManager, sessionID string) (*corev1beta1.Session, error) {
	sess := &corev1beta1.Session{}

	found, err := sm.GetSession(ctx, sessionID, sess)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return sess, nil
}

// newUnixTimeProto creates a UnixTime from the given google.protobuf.Timestamp, t
func newUnixTimeProto(t *timestamp.Timestamp) oidc.UnixTime {
	return oidc.UnixTime(t.Seconds)
}
