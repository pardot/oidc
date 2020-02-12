package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/pardot/oidc"
)

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

	oidcClient     *oidc.Client
	oidcClientInit sync.Once

	sessionStore   sessions.Store
	sessionStoreMu sync.Mutex
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
func (h *Handler) authenticateExisting(r *http.Request, session *sessions.Session) (*oidc.Claims, error) {
	ctx := r.Context()

	rawIDToken, ok := session.Values[sessionKeyOIDCIDToken].(string)
	if !ok {
		return nil, nil
	}

	oidccl, err := h.getOIDCClient(ctx)
	if err != nil {
		return nil, err
	}

	idToken, err := oidccl.VerifyRaw(ctx, h.ClientID, rawIDToken)
	if err != nil {
		// Attempt to refresh the token
		refreshToken, ok := session.Values[sessionKeyOIDCRefreshToken].(string)
		if !ok {
			return nil, nil
		}

		oidccl, err := h.getOIDCClient(ctx)
		if err != nil {
			return nil, err
		}

		token, err := oidccl.TokenSource(ctx, &oidc.Token{RefreshToken: refreshToken}).Token(ctx)
		if err != nil {
			return nil, nil
		}

		session.Values[sessionKeyOIDCIDToken] = token.RawIDToken
		session.Values[sessionKeyOIDCRefreshToken] = token.RefreshToken

		idToken = &token.Claims
	}

	return idToken, nil
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

	oidccl, err := h.getOIDCClient(ctx)
	if err != nil {
		return "", err
	}

	token, err := oidccl.Exchange(ctx, code)
	if err != nil {
		return "", err
	}

	session.Values[sessionKeyOIDCIDToken] = token.RawIDToken
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
	oidccl, err := h.getOIDCClient(r.Context())
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

	return oidccl.AuthCodeURL(state), nil
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

func (h *Handler) getOIDCClient(ctx context.Context) (*oidc.Client, error) {
	var initErr error
	h.oidcClientInit.Do(func() {
		h.oidcClient, initErr = oidc.DiscoverClient(ctx, h.Issuer, h.ClientID, h.ClientSecret, h.RedirectURL)
	})
	if initErr != nil {
		return nil, initErr
	}

	return h.oidcClient, nil
}

func ClaimsFromContext(ctx context.Context) *oidc.Claims {
	c, ok := ctx.Value(claimsContextKey{}).(*oidc.Claims)
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
