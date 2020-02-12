package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// Templates
var (
	tmplError = template.Must(template.New("").Parse(`
	  <h1>Error</h1>
		<hr>
		{{.}}
	`))

	tmplTokenIssued = template.Must(template.New("").Parse(`
	  <h1>Success</h1>
		<hr>
		Return to the terminal to continue.
	`))

	// RandomNonceGenerator generates a cryptographically-secure 128-bit random
	// nonce, encoded into a base64 string. Use with WithNonceGenerator.
	RandomNonceGenerator = func(ctx context.Context) (string, error) {
		b := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return "", err
		}

		return base64.StdEncoding.EncodeToString(b), nil
	}
)

const (
	ScopeGroups string = "groups"

	ACRMultiFactor         string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
	ACRMultiFactorPhysical string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"

	AMROTP string = "otp"
)

type LocalOIDCTokenSource struct {
	sync.Mutex

	endpoint     oauth2.Endpoint
	clientID     string
	clientSecret string

	credentialCache CredentialCache
	opener          Opener

	additionalScopes []string
	acrValues        []string
	nonceGenerator   func(context.Context) (string, error)
}

type LocalOIDCTokenSourceOpt func(s *LocalOIDCTokenSource)

var _ OIDCTokenSource = (*LocalOIDCTokenSource)(nil)

// NewLocalOIDCTokenSource creates a token source that command line (CLI)
// programs can use to fetch tokens from an OIDC Provider for use in
// authenticating clients to other systems (e.g., Kubernetes clusters, Docker
// registries, etc.)
//
// Example:
//     ctx := context.TODO()
//
//     provider, err := oidc.NewProvider(ctx, StagingURL)
//     if err != nil {
//       // handle err
//     }
//
//     ts, err := NewLocalOIDCTokenSource(provider, clientID, clientSecret)
//     if err != nil {
//       // handle err
//     }
//
//     token, err := ts.Token(ctx)
//     if err != nil {
//       // handle error
//     }
//
//     // use token
func NewLocalOIDCTokenSource(endpoint oauth2.Endpoint, clientID string, clientSecret string, opts ...LocalOIDCTokenSourceOpt) (*LocalOIDCTokenSource, error) {
	credentialCache := &MemoryWriteThroughCredentialCache{CredentialCache: BestCredentialCache()}

	s := &LocalOIDCTokenSource{
		endpoint:        endpoint,
		clientID:        clientID,
		clientSecret:    clientSecret,
		credentialCache: credentialCache,
		opener:          DetectOpener(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// WithAdditionalScopes requests additional scopes (e.g., groups)
func WithAdditionalScopes(scopes []string) LocalOIDCTokenSourceOpt {
	return func(s *LocalOIDCTokenSource) {
		s.additionalScopes = scopes
	}
}

func WithACRValues(acrValues []string) LocalOIDCTokenSourceOpt {
	return func(s *LocalOIDCTokenSource) {
		s.acrValues = acrValues
	}
}

// WithNonceGenerator specifies a function that generates a nonce. If a nonce
// generator is present, the credential cache will not be used.
func WithNonceGenerator(generator func(context.Context) (string, error)) LocalOIDCTokenSourceOpt {
	return func(s *LocalOIDCTokenSource) {
		s.nonceGenerator = generator
	}
}

// Token attempts to a fetch a token. The user will be required to open a URL
// in their browser and authenticate to the upstream IdP.
func (s *LocalOIDCTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	s.Lock()
	defer s.Unlock()

	scopes := []string{"openid", "profile", "email", "offline_access", "federated:id"}
	scopes = append(scopes, s.additionalScopes...)

	oauth2Config := &oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecret,
		Endpoint:     s.endpoint,
		Scopes:       scopes,
	}

	if s.nonceGenerator == nil {
		token, err := s.credentialCache.Get(s.endpoint.AuthURL, s.clientID, scopes, s.acrValues)
		if err != nil {
			s.debugf("cache get failed: %v", err)
		} else if token != nil && token.Valid() {
			// Token is present in cache and valid. Nothing more to do.
			return token, nil
		} else if token != nil {
			// Token is present in cache, but expired. Attempt to refresh
			// it. Errors are ignored because we want to simply force the
			// user back through the full authentication flow if a token
			// can't be refreshed.
			newToken, _ := oauth2Config.TokenSource(ctx, token).Token()
			if newToken != nil {
				if err := s.credentialCache.Set(s.endpoint.AuthURL, s.clientID, scopes, s.acrValues, newToken); err != nil {
					s.debugf("cache set failed: %v", err)
				}

				return newToken, nil
			}
		}
	}

	// Token was not present in cache, it could not be refreshed, or we're using
	// a nonce. Kick off the full auth flow.
	token, err := s.fetchToken(ctx, oauth2Config)
	if err != nil {
		return nil, err
	}

	if s.nonceGenerator == nil {
		if err := s.credentialCache.Set(s.endpoint.AuthURL, s.clientID, scopes, s.acrValues, token); err != nil {
			s.debugf("cache set failed: %v", err)
		}
	}

	return token, nil
}

func (s *LocalOIDCTokenSource) fetchToken(ctx context.Context, oauth2Config *oauth2.Config) (*oauth2.Token, error) {
	state, err := randomStateValue()
	if err != nil {
		return nil, err
	}

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()

	var calls int32
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.FormValue("error"); errMsg != "" {
			err := fmt.Errorf("%s: %s", errMsg, r.FormValue("error_description"))
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		code := r.FormValue("code")
		if code == "" {
			err := errors.New("no code in request")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		gotState := r.FormValue("state")
		if gotState == "" || gotState != state {
			err := errors.New("bad state")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, err.Error())
			return
		}

		if atomic.AddInt32(&calls, 1) > 1 {
			// Callback has been invoked multiple times, which should not happen.
			// Bomb out to avoid a blocking channel write and to float this as a bug.
			w.WriteHeader(http.StatusBadRequest)
			_ = tmplError.Execute(w, "callback invoked multiple times")
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = tmplTokenIssued.Execute(w, nil)

		resultCh <- result{code: code}
	})
	httpSrv := &http.Server{
		Addr:    "127.0.0.1:0", // let OS choose an open port for us
		Handler: mux,
	}

	ln, err := net.Listen("tcp", httpSrv.Addr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to bind socket")
	}
	defer func() { _ = ln.Close() }()
	tcpAddr := ln.Addr().(*net.TCPAddr)

	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Shutdown(ctx) }()

	authCodeOpts := []oauth2.AuthCodeOption{}
	if len(s.acrValues) > 0 {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("acr_values", strings.Join(s.acrValues, " ")))
	}
	if s.nonceGenerator != nil {
		nonce, err := s.nonceGenerator(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}

		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("nonce", nonce))
	}

	oauth2Config.RedirectURL = fmt.Sprintf("http://localhost:%d/callback", tcpAddr.Port)
	if err := s.opener.Open(ctx, oauth2Config.AuthCodeURL(state, authCodeOpts...)); err != nil {
		return nil, errors.Wrap(err, "failed to open URL")
	}

	var res result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res = <-resultCh:
		// continue
	}

	if res.err != nil {
		return nil, res.err
	}

	return oauth2Config.Exchange(ctx, res.code)
}

func (s *LocalOIDCTokenSource) debugf(pattern string, args ...interface{}) {
	if os.Getenv("OIDC_DEBUG") != "" {
		log.Printf(pattern, args...)
	}
}

func randomStateValue() (string, error) {
	const numBytes = 16

	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(b), nil
}
