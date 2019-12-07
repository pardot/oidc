package main

import (
	"context"
	"log"
	"net/http"

	"github.com/pardot/oidc/discovery"
	"golang.org/x/oauth2"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	iss := "http://localhost:8085"

	discoc, err := discovery.NewClient(ctx, iss)
	if err != nil {
		log.Fatalf("Failed discovery on issuer: %v", err)
	}

	oa2cfg := oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://localhost:8084/callback",

		Endpoint: oauth2.Endpoint{
			AuthURL:  discoc.Metadata().AuthorizationEndpoint,
			TokenURL: discoc.Metadata().TokenEndpoint,
		},

		Scopes: []string{"openid"},
	}

	svr := &server{
		oa2cfg: &oa2cfg,
	}

	log.Printf("Listening on: %s", "localhost:8084")
	err = http.ListenAndServe("localhost:8084", svr)
	if err != nil {
		log.Fatal(err)
	}
}
