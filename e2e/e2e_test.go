package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pardot/oidc"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/signer"
)

func TestE2E(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	for _, tc := range []struct {
		Name string
	}{
		{
			Name: "Simple authorization",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			callbackChan := make(chan string, 1)
			state := randomStateValue()

			cliSvr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if errMsg := req.FormValue("error"); errMsg != "" {
					t.Errorf("error returned to callback %s: %s", errMsg, req.FormValue("error_description"))

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				code := req.FormValue("code")
				if code == "" {
					t.Error("no code in callback response")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				gotState := req.FormValue("state")
				if gotState == "" || gotState != state {
					t.Errorf("returned state doesn't match request state")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				callbackChan <- code
			}))
			defer cliSvr.Close()

			cfg := &core.Config{
				AuthValidityTime: 1 * time.Minute,
				CodeValidityTime: 1 * time.Minute,
			}
			smgr := newStubSMGR()
			clientSource := &stubCS{
				ValidClients: map[string]csClient{
					clientID: csClient{
						Secret:      clientSecret,
						RedirectURI: cliSvr.URL,
					},
				},
			}

			oidcHandlers, err := core.New(cfg, smgr, clientSource, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			mux := http.NewServeMux()
			oidcSvr := httptest.NewServer(mux)
			defer oidcSvr.Close()

			mux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				ar, err := oidcHandlers.StartAuthorization(w, req)
				if err != nil {
					t.Fatalf("error starting authorization flow: %v", err)
				}

				// just finish it straight away
				if err := oidcHandlers.FinishAuthorization(w, req, ar.SessionID, &core.Authorization{Scopes: []string{"openid"}}); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
					return &core.TokenResponse{
						IDToken:                tr.PrefillIDToken(oidcSvr.URL, "test-sub", time.Now().Add(1*time.Minute)),
						AccessTokenValidUntil:  time.Now().Add(1 * time.Minute),
						IssueRefreshToken:      true,
						RefreshTokenValidUntil: time.Now().Add(2 * time.Minute),
					}, nil
				})
				if err != nil {
					t.Errorf("error in token endpoint: %v", err)
				}
			})

			mux.HandleFunc("/userinfo", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Userinfo(w, req, func(w io.Writer, _ *core.UserinfoRequest) error {
					fmt.Fprintf(w, `{
						"sub": "test-sub"
					}`)
					return nil
				})
				if err != nil {
					t.Errorf("error in userinfo endpoint: %v", err)
				}
			})

			// discovery endpoint
			md := &discovery.ProviderMetadata{
				Issuer:                oidcSvr.URL,
				AuthorizationEndpoint: oidcSvr.URL + "/authorization",
				TokenEndpoint:         oidcSvr.URL + "/token",
				JWKSURI:               oidcSvr.URL + "/jwks.json",
				UserinfoEndpoint:      oidcSvr.URL + "/userinfo",
			}

			discoh, err := discovery.NewConfigurationHandler(md, discovery.WithCoreDefaults())
			if err != nil {
				t.Fatalf("Failed to initialize discovery handler: %v", err)
			}
			mux.Handle("/.well-known/openid-configuration/", discoh)

			jwksh := discovery.NewKeysHandler(testSigner, 1*time.Second)
			mux.Handle("/jwks.json", jwksh)

			// set up client
			cl, err := oidc.DiscoverClient(ctx, oidcSvr.URL, clientID, clientSecret, cliSvr.URL)
			if err != nil {
				t.Fatalf("discovering client: %v", err)
			}

			client := &http.Client{}
			resp, err := client.Get(cl.AuthCodeURL(state))
			if err != nil {
				t.Fatalf("error getting auth URL: %v", err)
			}
			defer resp.Body.Close()

			var callbackCode string
			select {
			case callbackCode = <-callbackChan:
			case <-time.After(1 * time.Second):
				t.Fatal("waiting for callback timed out after 1s")
			}

			tok, err := cl.Exchange(ctx, callbackCode)
			if err != nil {
				t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
			}

			t.Logf("claims: %#v", tok.Claims)

			uir, err := cl.Userinfo(ctx, tok)
			if err != nil {
				t.Fatalf("error fetching userinfo: %v", err)
			}

			t.Logf("initial userinfo response: %#v", uir)

			for i := 0; i < 5; i++ {
				t.Logf("refresh iter: %d", i)
				currRT := tok.RefreshToken

				if err := smgr.expireAccessTokens(ctx); err != nil {
					t.Fatalf("expiring tokens: %v", err)
				}
				tok.Expiry = time.Now().Add(-1 * time.Second) // needs to line up with remote change, else we won't refresh

				uir, err := cl.Userinfo(ctx, tok)
				if err != nil {
					t.Fatalf("error fetching userinfo: %v", err)
				}

				if currRT == uir.Token.RefreshToken {
					t.Fatal("userinfo should result in new refresh token")
				}

				tok = uir.Token
			}

		})
	}
}

func randomStateValue() string {
	const numBytes = 16

	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}

// contains helpers used by multiple tests

type csClient struct {
	Secret      string
	RedirectURI string
}

type stubCS struct {
	ValidClients map[string]csClient
}

func (s *stubCS) IsValidClientID(clientID string) (ok bool, err error) {
	_, ok = s.ValidClients[clientID]
	return ok, nil
}

func (s *stubCS) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *stubCS) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, ok := s.ValidClients[clientID]
	return ok && clientSecret == cl.Secret, nil
}

func (s *stubCS) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, ok := s.ValidClients[clientID]
	return ok && redirectURI == cl.RedirectURI, nil
}

type stubSMGR struct {
	// sessions maps JSON session objects by their ID
	// JSON > proto here for better debug output
	sessions map[string]string
}

func newStubSMGR() *stubSMGR {
	return &stubSMGR{
		sessions: map[string]string{},
	}
}

func (s *stubSMGR) NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *stubSMGR) GetSession(_ context.Context, sessionID string, into core.Session) (found bool, err error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal([]byte(sess), into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess core.Session) error {
	if sess.ID() == "" {
		return fmt.Errorf("session has no ID")
	}
	strsess, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.ID()] = string(strsess)
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

// expireAccessTokens will set all the access token expirations to a time before
// now.
func (s *stubSMGR) expireAccessTokens(_ context.Context) error {
	for id, sd := range s.sessions {
		sm := map[string]interface{}{}
		if err := json.Unmarshal([]byte(sd), &sm); err != nil {
			return err
		}
		ati, ok := sm["access_token"]
		if !ok {
			continue // no access token in this session, skip
		}
		at := ati.(map[string]interface{})
		at["expires_at"] = time.Now().Add(-1 * time.Second).Format(time.RFC3339)
		sd, err := json.Marshal(sm)
		if err != nil {
			return err
		}
		s.sessions[id] = string(sd)
	}
	return nil
}

var testSigner = func() *signer.StaticSigner {
	key := mustGenRSAKey(512)

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
		Key:   key,
		KeyID: "testkey",
	}}

	verificationKeys := []jose.JSONWebKey{
		{
			Key:       key.Public(),
			KeyID:     "testkey",
			Algorithm: "RS256",
			Use:       "sig",
		},
	}

	return signer.NewStatic(signingKey, verificationKeys)
}()

func mustGenRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}
