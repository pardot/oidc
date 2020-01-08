package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/signer"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
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

			oidc, err := core.New(cfg, smgr, clientSource, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			mux := http.NewServeMux()
			oidcSvr := httptest.NewServer(mux)
			defer oidcSvr.Close()

			mux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				ar, err := oidc.StartAuthorization(w, req)
				if err != nil {
					t.Fatalf("error starting authorization flow: %v", err)
				}

				// just finish it straight away
				if err := oidc.FinishAuthorization(w, req, ar.SessionID, &core.Authorization{}); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
					return &core.TokenResponse{}, nil
				})
				if err != nil {
					t.Errorf("error in token endpoint: %v", err)
				}
			})

			oa2cfg := oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				RedirectURL:  cliSvr.URL,

				Endpoint: oauth2.Endpoint{
					AuthURL:  oidcSvr.URL + "/authorization",
					TokenURL: oidcSvr.URL + "/token",
				},

				Scopes: []string{"openid", "offline_access"},
			}

			client := &http.Client{}
			resp, err := client.Get(oa2cfg.AuthCodeURL(state))
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

			oa2Tok, err := oa2cfg.Exchange(ctx, callbackCode)
			if err != nil {
				t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
			}

			rawIDToken, ok := oa2Tok.Extra("id_token").(string)
			if !ok {
				t.Fatal("no id_token included in response")
			}

			_, err = testSigner.VerifySignature(ctx, rawIDToken)
			if err != nil {
				t.Errorf("want valid token, verification returned error: %v", err)
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

func (s *stubSMGR) GetSession(_ context.Context, sessionID string, into core.Session) (found bool, err error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := jsonpb.UnmarshalString(sess, into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess core.Session) error {
	if sess.GetId() == "" {
		return fmt.Errorf("session has no ID")
	}
	strsess, err := (&jsonpb.Marshaler{}).MarshalToString(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.GetId()] = strsess
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

var testSigner = func() core.Signer {
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
