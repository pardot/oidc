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
	authCodeKeyspace    = "oidc-auth-code"
	accessTokenKeyspace = "oidc-access-token"
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

// Config sets configuration values for the OIDC flow implementation
type Config struct {
	AuthValidityTime        time.Duration
	CodeValidityTime        time.Duration
	AccessTokenValidityTime time.Duration
}

// OIDC can be used to handle the various parts of the OIDC auth flow.
type OIDC struct {
	storage Storage
	clients ClientSource
	signer  Signer

	authValidityTime        time.Duration
	codeValidityTime        time.Duration
	accessTokenValidityTime time.Duration

	now func() time.Time
}

func NewOIDC(cfg *Config, storage Storage, clientSource ClientSource, signer Signer) (*OIDC, error) {
	return &OIDC{
		storage: storage,
		clients: clientSource,
		signer:  signer,

		authValidityTime:        cfg.AuthValidityTime,
		codeValidityTime:        cfg.CodeValidityTime,
		accessTokenValidityTime: cfg.AccessTokenValidityTime,

		now: time.Now,
	}, nil
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
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get auth request from storage")
	}

	if err := o.storage.Delete(req.Context(), authRequestKeyspace, authFlowID, arVer); err != nil {
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to delete auth request")
	}

	switch ar.ResponseType {
	case corestate.AuthRequest_CODE:
		return o.finishCodeAuthorization(w, req, ar, grantedScopes, metadata)
	default:
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", ar.ResponseType.String()))
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, authReq *corestate.AuthRequest, scopes []string, metadata proto.Message) error {
	tok, err := newToken()
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to generate code token")

	}

	pbtok, err := tok.ToPB()
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to conver token to proto")
	}

	var anym *any.Any

	if metadata != nil {
		var err error
		anym, err = ptypes.MarshalAny(metadata)
		if err != nil {
			return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal metadata to any")
		}
	}

	_ = scopes
	// TODO - granted scopes with the auth code. Or leave that to the metadata?
	ac := &corestate.AuthCode{
		Code:        pbtok,
		AuthRequest: authReq,
		Metadata:    anym,
	}

	if _, err := o.storage.PutWithExpiry(req.Context(), authCodeKeyspace, tok.ID(), 0, ac, o.now().Add(o.codeValidityTime)); err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to put authReq to storage")
	}

	redir, err := url.Parse(authReq.RedirectUri)
	if err != nil {
		return writeHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to parse authreq's URI")
	}

	codeResp := &codeAuthResponse{
		RedirectURI: redir,
		State:       authReq.State,
		Code:        tok.String(),
	}

	sendCodeAuthResponse(w, req, codeResp)

	return nil
}

type TokenRequest struct {
	IsRefresh        bool
	RefreshRequested bool

	Metadata *any.Any
}

type TokenResponse struct {
	AllowRefresh bool
	IDToken      IDToken

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
	tok, err := parseToken(req.Code)
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	// fetch the code, and make sure this isn't some replay. if it is, discard
	// both the code and the existing authorization code

	ac := &corestate.AuthCode{}
	acVer, err := o.storage.Get(ctx, authCodeKeyspace, tok.ID(), ac)
	if err != nil {
		// TODO - maybe a clearer error as to if this is transient, or something
		// fatal like code not existing.
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get auth code from storage", Cause: err}
	}

	ok, err := tok.Equal(tokenFromPB(ac.Code))
	if err != nil {
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok {
		if err := o.storage.Delete(ctx, authCodeKeyspace, tok.ID(), acVer); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete auth code from storage", Cause: err}
		}
		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	// The code already has a token associated with it. Assume we're under a
	// replay attack, and delete both the code and the issued access token (in
	// case the malicious request got in first)
	if ac.AccessToken != nil {
		at := tokenFromPB(ac.AccessToken)

		if err := o.storage.Delete(ctx, authCodeKeyspace, tok.ID(), acVer); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete auth code from storage", Cause: err}
		}

		atVer, err := o.storage.Get(ctx, accessTokenKeyspace, at.ID(), &corestate.AccessToken{})
		if err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to fetch access token", Cause: err}

		}

		if err := o.storage.Delete(ctx, accessTokenKeyspace, at.ID(), atVer); err != nil {
			return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete access token storage", Cause: err}
		}

		return nil, &tokenError{Code: tokenErrorCodeInvalidRequest, Description: "code already redeemed", Cause: err}
	}

	// validate the client
	cok, err := o.clients.ValidateClientSecret(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check client id & secret", Cause: err}

	}
	if !cok {
		return nil, &tokenError{Code: tokenErrorCodeUnauthorizedClient, Description: "", Cause: err}
	}

	// Call the handler with information about the request, and get the response.
	tr := &TokenRequest{
		IsRefresh:        false, // TODO
		RefreshRequested: false, // TODO
		Metadata:         ac.Metadata,
	}

	tresp, err := handler(tr)
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	// create a new access token
	atok, err := newToken()
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}

	}

	atokpb, err := atok.ToPB()
	if err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to create serializable token", Cause: err}
	}

	at := &corestate.AccessToken{
		AccessToken: atokpb,
		Metadata:    tresp.Metadata,
	}

	// Update the code with this token. We use this to track that the code is
	// now invalid rather than just deleting it, so we can detect potential
	// replay attacks and invalidate all issued credentials as a precaution.
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.1
	ac.AccessToken = at.AccessToken
	if _, err := o.storage.Put(ctx, authCodeKeyspace, tok.ID(), acVer, ac); err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to update access code", Cause: err}
	}

	// Save the access token with the right expiry
	if _, err := o.storage.PutWithExpiry(ctx, accessTokenKeyspace, atok.ID(), 0, at, o.now().Add(o.accessTokenValidityTime)); err != nil {
		return nil, &httpError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to put access token", Cause: err}
	}

	return &tokenResponse{
		AccessToken: atok.String(),
		TokenType:   "bearer",
		ExpiresIn:   o.accessTokenValidityTime,
		ExtraParams: map[string]interface{}{
			"id_token": "bbbbbb",
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
