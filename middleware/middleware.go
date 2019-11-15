package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type claims map[string]interface{}
type claimsContextKey struct{}

const (
	defaultSessionName = "oidc-middleware"

	sessionKeyOIDCState        = "oidc-state"
	sessionKeyOIDCReturnTo     = "oidc-return-to"
	sessionKeyOIDCIDToken      = "oidc-id-token"
	sessionKeyOIDCRefreshToken = "oidc-refresh-token"
)

// Handler wraps another http.Handler, protecting it with OIDC authentication.
type Handler struct {
	// Issuer is the URL to the OIDC issuer
	Issuer string
	// ClientID is a client ID for the relying party (the service authenticating
	// against the OIDC server)
	ClientID string
	// ClientSecret is a client secret for the relying party
	ClientSecret string
	// BaseURL is the base URL for this relying party. If it is not safe to
	// redirect the user to their original destination, they will be redirected
	// to this URL.
	BaseURL string
	// RedirectURL is the callback URL registered with the OIDC issuer for this
	// relying party
	RedirectURL string
	// Scopes is a list of scopes to request from the OIDC server. If nil, the
	// openid scope is requested.
	Scopes []string

	// SessionAuthenticationKey is a 32 or 64 byte random key used to
	// authenticate the session.
	SessionAuthenticationKey []byte
	// SessionEncryptionKey is a 16, 24 or 32 byte random key used to encrypt
	// the session. If nil, the session is not encrypted.
	SessionEncryptionKey []byte
	// SessionName is a name used for the session. If empty, a default session
	// name is used.
	SessionName string

	provider   *oidc.Provider
	providerMu sync.Mutex

	sessionStore   sessions.Store
	sessionStoreMu sync.Mutex

	clock func() time.Time
}

// Wrap returns an http.Handler that wraps the given http.Handler and
// provides OIDC authentication.
func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := h.getSession(r)

		// Check for a user that's already authenticated
		claims, err := h.authenticateExisting(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if claims != nil {
			if err := sessions.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Authentication successful
			r = r.WithContext(context.WithValue(r.Context(), claimsContextKey{}, claims))
			next.ServeHTTP(w, r)
			return
		}

		// Check for an authentication request finishing
		returnTo, err := h.authenticateCallback(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if returnTo != "" {
			if err := sessions.Save(r, w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, returnTo, http.StatusSeeOther)
			return
		}

		// Not authenticated. Kick off an auth flow.
		redirectURL, err := h.startAuthentication(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := sessions.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})
}

// authenticateExisting returns (claims, nil) if the user is authenticated,
// (nil, error) if a fatal error occurs, or (nil, nil) if the user is not
// authenticated but no fatal error occurred.
//
// This function may modify the session if a token is refreshed, so it must be
// saved afterward.
func (h *Handler) authenticateExisting(r *http.Request, session *sessions.Session) (claims, error) {
	ctx := r.Context()

	rawIDToken, ok := session.Values[sessionKeyOIDCIDToken].(string)
	if !ok {
		return nil, nil
	}

	provider, err := h.getProvider()
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: h.ClientID, Now: h.clock})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		// Attempt to refresh the token
		refreshToken, ok := session.Values[sessionKeyOIDCRefreshToken].(string)
		if !ok {
			return nil, nil
		}

		o2c, err := h.getOauth2Config()
		if err != nil {
			return nil, err
		}

		token, err := o2c.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
		if err != nil {
			return nil, nil
		}

		refreshedRawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			return nil, nil
		}

		refreshedIDToken, err := verifier.Verify(ctx, refreshedRawIDToken)
		if err != nil {
			return nil, nil
		}

		session.Values[sessionKeyOIDCIDToken] = refreshedRawIDToken
		session.Values[sessionKeyOIDCRefreshToken] = token.RefreshToken

		idToken = refreshedIDToken
	}

	c := make(claims)
	if err := idToken.Claims(&c); err != nil {
		return nil, nil
	}

	return c, nil
}

// authenticateCallback returns (returnTo, nil) if the user is authenticated,
// ("", error) if a fatal error occurs, or ("", nil) if the user is not
// authenticated but a fatal error did not occur.
//
// This function may modify the session if a token is authenticated, so it must be
// saved afterward.
func (h *Handler) authenticateCallback(r *http.Request, session *sessions.Session) (string, error) {
	ctx := r.Context()

	if r.Method != http.MethodGet {
		return "", nil
	}

	if qerr := r.URL.Query().Get("error"); qerr != "" {
		qdesc := r.URL.Query().Get("error_description")
		return "", fmt.Errorf("%s: %s", qerr, qdesc)
	}

	// If state or code are missing, this is not a callback
	state := r.URL.Query().Get("state")
	if state == "" {
		return "", nil
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", nil
	}

	wantState, _ := session.Values[sessionKeyOIDCState].(string)
	if wantState == "" || wantState != state {
		return "", fmt.Errorf("state did not match")
	}

	provider, err := h.getProvider()
	if err != nil {
		return "", err
	}

	o2c, err := h.getOauth2Config()
	if err != nil {
		return "", err
	}

	token, err := o2c.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("missing id_token")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: h.ClientID, Now: h.clock})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", err
	}

	c := make(claims)
	if err := idToken.Claims(&c); err != nil {
		return "", err
	}

	session.Values[sessionKeyOIDCIDToken] = rawIDToken
	session.Values[sessionKeyOIDCRefreshToken] = token.RefreshToken
	delete(session.Values, sessionKeyOIDCState)

	returnTo, ok := session.Values[sessionKeyOIDCReturnTo].(string)
	if !ok {
		returnTo = h.BaseURL
	}
	delete(session.Values, sessionKeyOIDCReturnTo)

	return returnTo, nil
}

func (h *Handler) startAuthentication(r *http.Request, session *sessions.Session) (string, error) {
	o2c, err := h.getOauth2Config()
	if err != nil {
		return "", err
	}

	delete(session.Values, sessionKeyOIDCIDToken)
	delete(session.Values, sessionKeyOIDCRefreshToken)

	state := randomState()
	session.Values[sessionKeyOIDCState] = state

	delete(session.Values, sessionKeyOIDCReturnTo)
	if r.Method == http.MethodGet {
		session.Values[sessionKeyOIDCReturnTo] = r.URL.RequestURI()
	}

	return o2c.AuthCodeURL(state), nil
}

func (h *Handler) getSession(r *http.Request) *sessions.Session {
	sessionName := h.SessionName
	if sessionName == "" {
		sessionName = defaultSessionName
	}

	if h.sessionStore != nil {
		session, _ := h.sessionStore.Get(r, sessionName)
		return session
	}

	h.sessionStoreMu.Lock()
	defer h.sessionStoreMu.Unlock()

	// Check again, holding lock
	if h.sessionStore != nil {
		session, _ := h.sessionStore.Get(r, sessionName)
		return session
	}

	h.sessionStore = sessions.NewCookieStore(h.SessionAuthenticationKey, h.SessionEncryptionKey)

	session, _ := h.sessionStore.Get(r, sessionName)
	return session
}

func (h *Handler) getProvider() (*oidc.Provider, error) {
	if h.provider != nil {
		return h.provider, nil
	}

	h.providerMu.Lock()
	defer h.providerMu.Unlock()

	// Check again while holding lock
	if h.provider != nil {
		return h.provider, nil
	}

	// The provided context must remain valid for the lifetime of the provider.
	provider, err := oidc.NewProvider(context.Background(), h.Issuer)
	if err != nil {
		return nil, err
	}
	h.provider = provider

	return h.provider, nil
}

func (h *Handler) getOauth2Config() (*oauth2.Config, error) {
	provider, err := h.getProvider()
	if err != nil {
		return nil, err
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(h.Scopes) > 0 {
		scopes = h.Scopes
	}

	return &oauth2.Config{
		ClientID:     h.ClientID,
		ClientSecret: h.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  h.RedirectURL,
		Scopes:       scopes,
	}, nil
}

func ClaimFromContext(ctx context.Context, claim string) interface{} {
	c, ok := ctx.Value(claimsContextKey{}).(claims)
	if !ok {
		return nil
	}

	return c[claim]
}

func ClaimsFromContext(ctx context.Context) map[string]interface{} {
	c, ok := ctx.Value(claimsContextKey{}).(claims)
	if !ok {
		return nil
	}

	return c
}

func randomState() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}
