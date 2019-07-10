package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/heroku/deci/oidcserver"
	"github.com/heroku/deci/signer"
	"github.com/heroku/deci/storage/disk"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	jose "gopkg.in/square/go-jose.v2"
)

func main() {
	l := logrus.New()

	var (
		issuer = kingpin.Flag("issuer", "Issuer URL to serve as").Default("http://127.0.0.1:5556/dex").String()
		dbPath = kingpin.Flag("db", "Database file to store state in").Default("./db/deci-simple.db").String()
		listen = kingpin.Flag("listen", "Addr to listen on").Default("127.0.0.1:5556").String()
	)
	kingpin.Parse()

	stor, err := disk.New(*dbPath, 0644)
	if err != nil {
		l.WithError(err).Fatal("Failed to initialize storage")
	}

	privs, pubs := mustGenKeyset(2)
	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: privs.Keys[0]}
	signer := signer.NewStatic(signingKey, pubs.Keys)

	connectors := map[string]oidcserver.Connector{
		"simple": &simpleConnector{
			Identity: oidcserver.Identity{
				UserID:        "abc",
				Username:      "abc",
				Email:         "abc@def.com",
				EmailVerified: true,
				Groups:        []string{"group"},
			},
		},
	}

	clients := &simpleClientSource{
		Clients: map[string]*oidcserver.Client{
			"example-app": {
				ID:           "example-app",
				Secret:       "ZXhhbXBsZS1hcHAtc2VjcmV0",
				RedirectURIs: []string{"http://127.0.0.1:5555/callback"},
			},
		},
	}

	server, err := oidcserver.New(*issuer, stor, signer, connectors, clients, oidcserver.WithLogger(l))
	if err != nil {
		l.WithError(err).Fatal("Failed to construct server")
	}

	l.Infof("Listening on %s", *listen)
	l.WithError(http.ListenAndServe(*listen, server)).Fatal()
}

type simpleConnector struct {
	Identity oidcserver.Identity

	auth oidcserver.Authenticator
}

func (s *simpleConnector) Initialize(auth oidcserver.Authenticator) error {
	s.auth = auth
	return nil
}

// LoginPage just automatically approves the connection and finalizes the flow
func (s *simpleConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr oidcserver.LoginRequest) {
	// just auto mark the session as good, and redirect the user to the final page
	ret, err := s.auth.Authenticate(r.Context(), lr.AuthID, s.Identity)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal error: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

// Refresh updates the identity during a refresh token request.
func (s *simpleConnector) Refresh(ctx context.Context, sc oidcserver.Scopes, identity oidcserver.Identity) (oidcserver.Identity, error) {
	return s.Identity, nil
}

type simpleClientSource struct {
	Clients map[string]*oidcserver.Client
}

func (s *simpleClientSource) GetClient(id string) (*oidcserver.Client, error) {
	if s.Clients == nil {
		return nil, errors.New("Clients not initialized")
	}
	c, ok := s.Clients[id]
	if !ok {
		return nil, fmt.Errorf("Client %q not found", id)
	}
	return c, nil
}

// mustGenKeyset returns a set of public and private keys, with numKeys in each.
func mustGenKeyset(numKeys int) (privs *jose.JSONWebKeySet, pubs *jose.JSONWebKeySet) {
	const (
		alg = jose.RS256
		use = "sig"
	)

	privs, pubs = new(jose.JSONWebKeySet), new(jose.JSONWebKeySet)
	for i := 0; i < numKeys; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		b := make([]byte, 5)
		_, err = rand.Read(b)
		if err != nil {
			log.Fatal(err)
		}
		kid := base32.StdEncoding.EncodeToString(b)
		priv := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: string(alg), Use: use}
		pub := jose.JSONWebKey{Key: key.Public(), KeyID: kid, Algorithm: string(alg), Use: use}
		if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
			panic("invalid keys were generated")
		}
		privs.Keys = append(privs.Keys, priv)
		pubs.Keys = append(pubs.Keys, pub)
	}
	return privs, pubs
}
