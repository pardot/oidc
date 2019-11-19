package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pardot/oidc/storage/memory"
	"golang.org/x/oauth2"
)

type csClient struct {
	Secret      string
	RedirectURI string
}

type stubCS struct {
	validClients map[string]csClient
}

func (s *stubCS) IsValidClientID(clientID string) (ok bool, err error) {
	_, ok = s.validClients[clientID]
	return ok, nil
}

func (s *stubCS) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *stubCS) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, ok := s.validClients[clientID]
	return ok && clientSecret == cl.Secret, nil
}

func (s *stubCS) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, ok := s.validClients[clientID]
	return ok && redirectURI == cl.RedirectURI, nil
}

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
				if err := req.ParseForm(); err != nil {
					t.Fatalf("failed to parse form: %v", err)
				}

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

			oidc := &OIDC{
				clients: &stubCS{
					validClients: map[string]csClient{
						clientID: csClient{
							Secret:      clientSecret,
							RedirectURI: cliSvr.URL,
						},
					},
				},

				storage: memory.New(),

				authValidityTime:        1 * time.Minute,
				codeValidityTime:        1 * time.Minute,
				accessTokenValidityTime: 1 * time.Minute,

				now: time.Now,
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
				if err := oidc.FinishAuthorization(w, req, ar.AuthID, []string{}, nil); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidc.Token(w, req, func(tr *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
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

				Scopes: []string{"openid"},
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

			t.Logf("id token: %s", rawIDToken)
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
