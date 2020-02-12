package main

import (
	"context"
	"flag"
	"log"

	"github.com/pardot/oidc"
	"github.com/pardot/oidc/clitoken"
	"github.com/pardot/oidc/tokencache"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := struct {
		Issuer       string
		ClientID     string
		ClientSecret string
		Refresh      bool
	}{
		Issuer:       "http://localhost:8085",
		ClientID:     "cli",
		ClientSecret: "cli-client-secret",
		Refresh:      true,
	}

	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "issuer")
	flag.StringVar(&cfg.ClientID, "client-id", cfg.ClientID, "client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", cfg.ClientSecret, "client secret")
	flag.BoolVar(&cfg.Refresh, "redirect-url", cfg.Refresh, "request refreshable token")

	flag.Parse()

	var opts []oidc.ClientOpt
	if cfg.Refresh {
		opts = append(opts, oidc.WithAdditionalScopes([]string{oidc.ScopeOfflineAccess}))
	}

	client, err := oidc.DiscoverClient(ctx, cfg.Issuer, cfg.ClientID, cfg.ClientSecret, "", opts...)
	if err != nil {
		log.Fatalf("failed to discover issuer: %v", err)
	}

	clis, err := clitoken.NewSource(client)
	if err != nil {
		log.Fatalf("getting cli token source: %v", err)
	}

	ts := tokencache.TokenSource(clis, cfg.Issuer, cfg.ClientID, tokencache.WithRefreshClient(client))

	tok, err := ts.Token(ctx)
	if err != nil {
		log.Fatalf("getting token: %v", err)
	}

	log.Printf("Access Token: %s", tok.AccessToken)
	log.Printf("Refresh Token: %s", tok.RefreshToken)
	log.Printf("Access Token expires: %s", tok.Expiry.String())
	log.Printf("ID token: %s", tok.IDToken)
	log.Printf("Claims expires: %s", tok.Claims.Expiry.Time().String())
	log.Printf("Claims: %v", tok.Claims)
}
