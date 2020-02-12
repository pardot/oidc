package clitoken

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
	"sync"
	"sync/atomic"

	"github.com/pardot/oidc"
	"github.com/pkg/errors"
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

	client *oidc.Client

	opener Opener

	nonceGenerator func(context.Context) (string, error)
}

type LocalOIDCTokenSourceOpt func(s *LocalOIDCTokenSource)

var _ oidc.TokenSource = (*LocalOIDCTokenSource)(nil)

// NewSource creates a token source that command line (CLI) programs can use to
// fetch tokens from an OIDC Provider for use in authenticating clients to other
// systems (e.g., Kubernetes clusters, Docker registries, etc.). The client
// should be configured with any scopes/acr values that are required.
//
// This will trigger the auth flow each time, in practice the result should be
// cached.
//
// Example:
//     ctx := context.TODO()
//
//     client, err := oidc.DiscoverClient(ctx, StagingURL, ClientID, ClientSecret, "")
//     if err != nil {
//       // handle err
//     }
//
//     ts, err := NewLocalOIDCTokenSource(client, clientID, clientSecret)
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
func NewSource(client *oidc.Client, clientID string, clientSecret string, opts ...LocalOIDCTokenSourceOpt) (*LocalOIDCTokenSource, error) {

	s := &LocalOIDCTokenSource{
		client: client,
		opener: DetectOpener(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// WithNonceGenerator specifies a function that generates a nonce. If a nonce
// generator is present, this token source should not be wrapped in any kind of
// cache.
func WithNonceGenerator(generator func(context.Context) (string, error)) LocalOIDCTokenSourceOpt {
	return func(s *LocalOIDCTokenSource) {
		s.nonceGenerator = generator
	}
}

// Token attempts to a fetch a token. The user will be required to open a URL
// in their browser and authenticate to the upstream IdP.
func (s *LocalOIDCTokenSource) Token(ctx context.Context) (*oidc.Token, error) {
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

	authCodeOpts := []oidc.AuthCodeOption{
		oidc.SetRedirectURL(fmt.Sprintf("http://localhost:%d/callback", tcpAddr.Port)),
	}
	if s.nonceGenerator != nil {
		nonce, err := s.nonceGenerator(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}

		authCodeOpts = append(authCodeOpts, oidc.SetNonce(nonce))
	}

	authURL := s.client.AuthCodeURL(state, authCodeOpts...)

	if err := s.opener.Open(ctx, authURL); err != nil {
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

	return s.client.Exchange(ctx, res.code)
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
