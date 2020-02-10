package client

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/idtoken"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type KeySource interface {
	GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error)
}

type Client struct {
	md *discovery.ProviderMetadata
	ks KeySource

	o2cfg oauth2.Config
}

func DiscoverClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string) (*Client, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	return &Client{
		md: cl.Metadata(),
		ks: cl,
		o2cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cl.Metadata().AuthorizationEndpoint,
				TokenURL: cl.Metadata().TokenEndpoint,
			},
			Scopes:      []string{"openid", "offline_access"},
			RedirectURL: redirectURL,
		},
	}, nil
}

type authCodeCfg struct{}

type AuthCodeOption func(*authCodeCfg)

// AuthCodeURL returns the URL the user should be directed to to initiate the
// code auth flow.
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	return c.o2cfg.AuthCodeURL(state)
}

type Token struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	Claims       idtoken.Claims
	RawIDToken   string
}

// Exchange the returned code for a set of tokens
func (c *Client) Exchange(ctx context.Context, code string) (*Token, error) {
	t, err := c.o2cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %v", err)
	}

	tokraw := t.Extra("id_token")
	raw, ok := tokraw.(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("response did not contain id_token")
	}

	cl, err := c.VerifyRaw(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %v", err)
	}

	return &Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
		Claims:       *cl,
		RawIDToken:   raw,
	}, nil
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (c *Client) VerifyRaw(ctx context.Context, raw string, opts ...VerifyOpt) (*idtoken.Claims, error) {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("failed parsing raw: %v", err)
	}

	var kid string
	for _, h := range tok.Headers {
		if h.KeyID != "" {
			kid = h.KeyID
			break
		}
	}
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}

	key, err := c.ks.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("fetching key %s: %v", kid, err)
	}

	// parse it into the library claims so we can use their verification code
	cl := jwt.Claims{}
	if err := tok.Claims(key, &cl); err != nil {
		return nil, fmt.Errorf("verifying token claims: %v", err)
	}

	log.Printf("validate %s against issuer: %s", raw, c.md.Issuer)

	if err := cl.Validate(jwt.Expected{
		Issuer:   c.md.Issuer,
		Audience: jwt.Audience([]string{c.o2cfg.ClientID}),
		Time:     time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("claim validation: %v", err)
	}

	// now parse it in to our type to return
	idt := idtoken.Claims{}
	if err := tok.Claims(key, &idt); err != nil {
		return nil, fmt.Errorf("verifying token claims: %v", err)
	}

	return &idt, nil
}
