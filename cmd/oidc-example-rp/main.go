package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/pardot/oidc/client"
)

const (
	clientID     = "client-id"
	clientSecret = "client-secret"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := struct {
		Issuer       string
		ClientID     string
		ClientSecret string
		RedirectURL  string
	}{
		Issuer:       "http://localhost:8085",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8084/callback",
	}

	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "issuer")
	flag.StringVar(&cfg.ClientID, "client-id", cfg.ClientID, "client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", cfg.ClientSecret, "client secret")
	flag.StringVar(&cfg.RedirectURL, "redirect-url", cfg.RedirectURL, "redirect URL")

	flag.Parse()

	cli, err := client.DiscoverClient(ctx, cfg.Issuer, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL)
	if err != nil {
		log.Fatalf("failed to discover issuer: %v", err)
	}

	svr := &server{
		oidccli: cli,
	}

	log.Printf("Listening on: %s", "http://localhost:8084")
	err = http.ListenAndServe("localhost:8084", svr)
	if err != nil {
		log.Fatal(err)
	}
}
