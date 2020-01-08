package client

import (
	"context"

	"github.com/pardot/oidc/idtoken"
	"golang.org/x/oauth2"
)

type Client struct {
}

func New(ctx context.Context, issuer string) (*Client, error) {
	return &Client{}, nil
}

func (c *Client) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{}
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (c *Client) Verify(ctx context.Context, token, audience string, opts ...VerifyOpt) (*idtoken.Claims, error) {
	return nil, nil
}
