package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	corestate "github.com/pardot/oidc/proto/deci/corestate/v1beta1"
	"github.com/pardot/oidc/storage"
	"gopkg.in/square/go-jose.v2"
)

const (
	authRequestKeyspace = "oidc-auth-request"
	authSessionKeyspace = "oidc-session"
)

// Storage is used to maintain authorization flow state.
type Storage storage.Storage

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
	storage Storage
	clients ClientSource
	signer  Signer

	authValidityTime time.Duration
	codeValidityTime time.Duration

	now func() time.Time
}

func NewOIDC(cfg *Config, storage Storage, clientSource ClientSource, signer Signer) (*OIDC, error) {
	o := &OIDC{
		storage: storage,
		clients: clientSource,
		signer:  signer,

		authValidityTime: cfg.AuthValidityTime,
		codeValidityTime: cfg.CodeValidityTime,

		now: time.Now,
	}

	if o.authValidityTime == time.Duration(0) {
		o.authValidityTime = DefaultAuthValidityTime
	}
	if o.codeValidityTime == time.Duration(0) {
		o.codeValidityTime = DefaultCodeValidityTime
	}

	return o, nil
}

type AuthorizationResponse struct {
	AuthID string
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
func (o *OIDC) StartAuthorization(w http.ResponseWriter, req *http.Request) (*AuthorizationResponse, error) {
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

	authFlowID := mustGenerateID()

	ar := &corestate.AuthRequest{
		ClientId:    authreq.ClientID,
		RedirectUri: redir.String(),
		State:       authreq.State,
		Scopes:      authreq.Scopes,
		Nonce:       req.FormValue("nonce"),
	}

	switch authreq.ResponseType {
	case responseTypeCode:
		ar.ResponseType = corestate.AuthRequest_CODE
	default:
		return nil, writeAuthError(w, req, redir, authErrorCodeUnsupportedResponseType, authreq.State, "response type must be code", nil)
	}

	if _, err := o.storage.PutWithExpiry(req.Context(), authRequestKeyspace, authFlowID, 0, ar, o.now().Add(o.authValidityTime)); err != nil {
		return nil, writeAuthError(w, req, redir, authErrorCodeErrServerError, authreq.State, "failed to persist auth request", err)
	}

	return &AuthorizationResponse{
		AuthID: authFlowID,
	}, nil
}

// FinishAuthorization should be called once the consumer has validated the
// identity of the user. This will return the appropriate response directly to
// the passed http context, which should be considered finalized when this is
// called. Note: This does not have to be the same http request in which
// Authorization was started, but the authID field will need to be tracked and
// consistent.
//
// The scopes this request has been granted with should be included. Metadata
// can be passed, that will be made available to requests to userinfo and token
// issue/refresh. This is application-specific, and should be used to track
// information needed to serve those endpoints.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (o *OIDC) FinishAuthorization(w http.ResponseWriter, req *http.Request, authFlowID string, grantedScopes []string, metadata proto.Message) error {
	ar := &corestate.AuthRequest{}
	arVer, err := o.storage.Get(req.Context(), authRequestKeyspace, authFlowID, ar)
	if err != nil {
		if storage.IsNotFoundErr(err) {
			return writeHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "auth request not found in storage")
		}
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get auth request from storage")
	}

	if err := o.storage.Delete(req.Context(), authRequestKeyspace, authFlowID, arVer); err != nil {
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to delete auth request")
	}

	var anym *any.Any

	if metadata != nil {
		var err error
		anym, err = ptypes.MarshalAny(metadata)
		if err != nil {
			return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal metadata to any")
		}
	}

	// start a session with the passed info, we'll complete it in the
	// appropriate flow
	sessID := mustGenerateID()
	authSess := &corestate.Session{
		ClientId: ar.ClientId,
		Scopes:   grantedScopes,
		Metadata: anym,
	}

	switch ar.ResponseType {
	case corestate.AuthRequest_CODE:
		return o.finishCodeAuthorization(w, req, ar, sessID, authSess)
	default:
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", ar.ResponseType.String()))
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, authReq *corestate.AuthRequest, sessID string, authSess *corestate.Session) error {
	ucode, scode, err := newToken(sessID, corestate.TokenType_AUTH_CODE, o.now().Add(o.codeValidityTime))
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to generate code token")
	}

	code, err := marshalToken(ucode)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal code token")
	}

	authSess.AuthCode = scode

	if _, err := o.storage.PutWithExpiry(req.Context(), authSessionKeyspace, sessID, 0, authSess, o.sessionExpiry(0, 0)); err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to put authReq to storage")
	}

	redir, err := url.Parse(authReq.RedirectUri)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to parse authreq's URI")
	}

	codeResp := &codeAuthResponse{
		RedirectURI: redir,
		State:       authReq.State,
		Code:        code,
	}

	sendCodeAuthResponse(w, req, codeResp)

	return nil
}

// TokenRequest encapsulates the information from the request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// ClientID of the client this session is bound to.
	ClientID string
	// GrantType indicates the grant that was requested for this invocation of
	// the token endpoint
	GrantType GrantType
	// RefreshRequested is true if the offline_access scope was requested.å
	RefreshRequested bool

	// Metadata is the application-specific state that was attached to this session.
	Metadata *any.Any
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// AllowRefresh indicates if we should issue a refresh token.
	AllowRefresh bool

	// IDToken is returned as the id_token for the request to this endpoint. It
	// is up to the application to store _all_ the desired information in the
	// token correctly, and to obey the OIDC spec. The handler will make no
	// changes to this token.
	IDToken IDToken

	// AccessTokenValidFor indicates how long the returned authorization token
	// should be valid for.
	AccessTokenValidFor time.Duration
	// RefreshTokenValidFor indicates how long the returned refresh token should
	// be valid for, assuming one is issued.
	RefreshTokenValidFor time.Duration

	// Metadata is the application-specific state that should be attached to this session.
	Metadata *any.Any
}

// Token is used to handle the access token endpoint for code flow requests.
// This can handle both the initial access token request, as well as subsequent
// calls for refreshes.
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
	ucode, err := unmarshalToken(req.Code)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	if ucode.TokenType != corestate.TokenType_AUTH_CODE {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: fmt.Errorf("passed token was the wrong type")}
	}

	// fetch the corresponding session

	sess := &corestate.Session{}
	sessVer, err := o.storage.Get(ctx, authSessionKeyspace, ucode.SessionId, sess)
	if err != nil {
		if storage.IsNotFoundErr(err) {
			return nil, &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "token expired"}
		}
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get session from storage", Cause: err}
	}

	ok, err := tokensMatch(ucode, sess.AuthCode)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok {
		// if we're passed an invalid code, assume we're under attack and drop the session
		if err := o.storage.Delete(ctx, authSessionKeyspace, ucode.SessionId, sessVer); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	// The session already has a token associated with it. Assume we're under a
	// replay attack, and drop the session
	if len(sess.AccessTokens) > 0 {
		if err := o.storage.Delete(ctx, authSessionKeyspace, ucode.SessionId, sessVer); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete auth code from storage", Cause: err}
		}

		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "code already redeemed", Cause: err}
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
		return nil, &tokenError{Code: tokenErrorCodeUnauthorizedClient, Description: ""}
	}

	// Call the handler with information about the request, and get the response.
	tr := &TokenRequest{
		ClientID:         req.ClientID,
		GrantType:        req.GrantType,
		RefreshRequested: strsContains(sess.Scopes, "offline_access"),
		Metadata:         sess.Metadata,
	}

	tresp, err := handler(tr)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	var anym *any.Any
	if tresp.Metadata != nil {
		a, err := ptypes.MarshalAny(tresp.Metadata)
		if err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal metadata", Cause: err}
		}
		anym = a
	}
	sess.Metadata = anym

	// create a new access token
	useratok, satok, err := newToken(ucode.SessionId, corestate.TokenType_ACCESS_TOKEN, o.now().Add(tresp.AccessTokenValidFor))
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}

	}
	if sess.AccessTokens == nil {
		sess.AccessTokens = map[string]*corestate.StoredToken{}
	}
	sess.AccessTokens[useratok.TokenId] = satok

	// TODO - generate refresh token if requested/allowed

	// TODO - refresh
	if _, err := o.storage.PutWithExpiry(ctx, authSessionKeyspace, ucode.SessionId, sessVer, sess, o.sessionExpiry(tresp.AccessTokenValidFor, tresp.RefreshTokenValidFor)); err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to put access token", Cause: err}
	}

	accessTok, err := marshalToken(useratok)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal user token", Cause: err}
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
		AccessToken: accessTok,
		TokenType:   "bearer",
		ExpiresIn:   tresp.AccessTokenValidFor,
		ExtraParams: map[string]interface{}{
			"id_token": string(sidt),
		},
	}, nil
}

type UserinfoRequest struct {
	Metadata *any.Any
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// response data to the passed JSON encoder. This could be the stored claims if
// the ID Token contents are sufficient, otherwise this should be the desired
// response. This will return the desired information in an unsigned format.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (o *OIDC) Userinfo(w http.ResponseWriter, req *http.Request, handler func(w *json.Encoder, uireq *UserinfoRequest) error) (err error) {
	return nil
}

// mustGenerateID returns a new, unique identifier. If it can't, it will panic
func mustGenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// sessionExpiry calculates the time the session should expire. This is the greater of the
// various tokens that were issued.
func (o *OIDC) sessionExpiry(accessTokenValidity, refreshTokenValidity time.Duration) time.Time {
	var max time.Duration
	for _, d := range []time.Duration{o.codeValidityTime, accessTokenValidity, refreshTokenValidity} {
		if int64(d) > int64(max) {
			max = d
		}
	}

	return o.now().Add(max)
}

func strsContains(strs []string, s string) bool {
	for _, str := range strs {
		if str == s {
			return true
		}
	}
	return false
}
