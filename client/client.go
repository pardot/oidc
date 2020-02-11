package client

import (
	"context"
	"fmt"
	"time"

	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/idtoken"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
)

const (
	// ScopeOfflineAccess requests a refresh token
	ScopeOfflineAccess = "offline_access"
)

type KeySource interface {
	GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error)
}

type Client struct {
	Verifier

	md *discovery.ProviderMetadata
	ks KeySource

	o2cfg oauth2.Config
}

// ClientOpt can be used to customize the client
// nolint:golint
type ClientOpt func(*Client)

// WithScopes will set the given scopes on all AuthCode requests. This will
// override the default of "openid".
func WithScopes(scopes []string) ClientOpt {
	return func(c *Client) {
		c.o2cfg.Scopes = scopes
	}
}

func DiscoverClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, opts ...ClientOpt) (*Client, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	c := &Client{
		Verifier: Verifier{
			md: cl.Metadata(),
			ks: cl,
		},
		md: cl.Metadata(),
		ks: cl,
		o2cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cl.Metadata().AuthorizationEndpoint,
				TokenURL: cl.Metadata().TokenEndpoint,
			},
			Scopes:      []string{"openid"},
			RedirectURL: redirectURL,
		},
	}

	for _, o := range opts {
		o(c)
	}

	return c, nil
}

type authCodeCfg struct{}

type AuthCodeOption func(*authCodeCfg)

// AuthCodeURL returns the URL the user should be directed to to initiate the
// code auth flow.
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	return c.o2cfg.AuthCodeURL(state)
}

// Token encapsulates the data returned from the token endpoint
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

	return c.oauth2Token(ctx, t)
}

func (c *Client) oauth2Token(ctx context.Context, t *oauth2.Token) (*Token, error) {
	tokraw := t.Extra("id_token")
	raw, ok := tokraw.(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("response did not contain id_token")
	}

	cl, err := c.VerifyRaw(ctx, c.o2cfg.ClientID, raw)
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

type wrapTokenSource struct {
	ts oauth2.TokenSource
	c  *Client
}

func (c *Client) TokenSource(ctx context.Context, t *Token) TokenSource {
	o2tok := &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}

	return &wrapTokenSource{
		ts: c.o2cfg.TokenSource(ctx, o2tok),
		c:  c,
	}
}

func (w *wrapTokenSource) Token(ctx context.Context) (*Token, error) {
	o2tok, err := w.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("getting oauth2 token: %v", err)
	}

	return w.c.oauth2Token(ctx, o2tok)
}
