package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pardot/oidc/discovery"
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

	acrValues  []string
	enforceAcr bool
}

// ClientOpt can be used to customize the client
// nolint:golint
type ClientOpt func(*Client)

// WithAdditionalScopes will set the given scopes on all AuthCode requests. This is in addition to the default "openid" scopes
func WithAdditionalScopes(scopes []string) ClientOpt {
	return func(c *Client) {
		c.o2cfg.Scopes = append(c.o2cfg.Scopes, scopes...)
	}
}

// WithACRValues sets the ACR values to request. If enforce is true, the
// resultant ID token will be checked to make sure it matches one of the
// requested values, and an error will be returned if it doesn't
func WithACRValues(acrValues []string, enforce bool) ClientOpt {
	return func(c *Client) {
		c.acrValues = acrValues
		c.enforceAcr = enforce
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

type authCodeCfg struct {
	nonce      string
	addlScopes []string
}

// AuthCodeOption can be used to modify the auth code URL that is generated.
type AuthCodeOption func(*authCodeCfg)

// SetNonce sets the nonce for this request
func SetNonce(nonce string) AuthCodeOption {
	return func(cfg *authCodeCfg) {
		cfg.nonce = nonce
	}
}

// AddScopes adds additional scopes to this URL only
func AddScopes(scopes []string) AuthCodeOption {
	return func(cfg *authCodeCfg) {
		cfg.addlScopes = scopes
	}
}

// AuthCodeURL returns the URL the user should be directed to to initiate the
// code auth flow.
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	accfg := &authCodeCfg{}
	for _, o := range opts {
		o(accfg)
	}

	aopts := []oauth2.AuthCodeOption{}

	if len(c.acrValues) > 0 {
		aopts = append(aopts, oauth2.SetAuthURLParam("acr_values", strings.Join(c.acrValues, " ")))
	}

	if accfg.nonce != "" {
		aopts = append(aopts, oauth2.SetAuthURLParam("nonce", accfg.nonce))
	}

	oc := &c.o2cfg
	oc.Scopes = append(oc.Scopes, accfg.addlScopes...)

	return oc.AuthCodeURL(state, aopts...)
}

// Token encapsulates the data returned from the token endpoint
type Token struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Claims       Claims    `json:"claims,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

// Valid if it contains an ID token, and the token's claims are in their
// validity period.
func (t *Token) Valid() bool {
	// TODO - nbf claim?
	return t.Claims.Expiry.Time().After(time.Now()) &&
		t.IDToken != ""
}

// Type of the token
func (t *Token) Type() string {
	// only thing we support for now
	return "Bearer"
}

// SetRedirectURL updates the redirect URL this client is configured for.
func (c *Client) SetRedirectURL(redirectURL string) {
	c.o2cfg.RedirectURL = redirectURL
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

	if c.enforceAcr {
		var found bool
		for _, acr := range c.acrValues {
			if cl.ACR != "" && cl.ACR == acr {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("want one of ACR %v, got %s", c.acrValues, cl.ACR)
		}
	}

	return &Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
		Claims:       *cl,
		IDToken:      raw,
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
