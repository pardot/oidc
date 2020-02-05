package client

import (
	"context"
	"fmt"
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
	md discovery.ProviderMetadata
	ks KeySource

	clientID     string
	clientSecret string
}

func Discover(ctx context.Context, issuer, clientID, clientSecret string) (*Client, error) {
	return &Client{}, nil
}

func (c *Client) Endpoint(redirectURI string) oauth2.Endpoint {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.md.AuthorizationEndpoint,
			TokenURL: c.md.TokenEndpoint,
		},
		RedirectURL: redirectURI,
	}

}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (c *Client) VerifyToken(ctx context.Context, tok *oauth2.Token, opts ...VerifyOpt) (*idtoken.Claims, error) {
	tokraw := tok.Extra("id_token")
	raw, ok := tokraw.(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("response did not contain id_token")
	}

	return c.VerifyRaw(ctx, raw, opts...)
}

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

	if err := cl.Validate(jwt.Expected{
		Issuer:   c.md.Issuer,
		Audience: jwt.Audience([]string{c.clientID}),
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
