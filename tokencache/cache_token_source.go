package tokencache

import (
	"context"
	"fmt"

	"github.com/pardot/oidc"
)

type cachingTokenSource struct {
	src   oidc.TokenSource
	cache CredentialCache

	iss       string
	aud       string
	scopes    []string
	acrValues []string

	client *oidc.Client
}

type TokenSourceOpt func(*cachingTokenSource)

// WithCache uses the passed cache
func WithCache(cc CredentialCache) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.cache = cc
	}
}

// WithScopes keys the cache with the additional scopes. Used where tokens need
// to be differed for different scopes.
func WithScopes(scopes []string) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.scopes = scopes
	}
}

// WithACRValues keys the cache with the ACR values. Used where tokens of
// different ACR values are tracked.
func WithACRValues(acrValues []string) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.acrValues = acrValues
	}
}

// WithRefreshClient will add a configured client to the source. This will be
// used to fetch a new token if the cached token is expired and has a
// RefreshToken
func WithRefreshClient(client *oidc.Client) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.client = client
	}
}

// TokenSource wraps an oidc.TokenSource, caching the token results locally so
// they survive cross-process execution. The result of BestCredentialCache is
// used for the cache, this can be overridden with the WithCache option. Items
// are stored in the cache keyed by their issuer and audience, WithScopes and
// WithACRValues can be used to further refine the keying where differentiation
// is required on these values.
func TokenSource(src oidc.TokenSource, issuer, audience string, opts ...TokenSourceOpt) oidc.TokenSource {
	ts := &cachingTokenSource{
		src: src,
		iss: issuer,
		aud: audience,
	}

	for _, o := range opts {
		o(ts)
	}

	if ts.cache == nil {
		ts.cache = &MemoryWriteThroughCredentialCache{CredentialCache: BestCredentialCache()}
	}

	return ts
}

// Token checks the cache for a token, and if it exists and is valid returns it.
// Otherwise, it will call the upstream Token source and cache the result,
// before returning it.
func (c *cachingTokenSource) Token(ctx context.Context) (*oidc.Token, error) {
	token, err := c.cache.Get(c.iss, c.aud, c.scopes, c.acrValues)
	if err != nil {
		return nil, fmt.Errorf("cache get: %v", err)
	}

	if token != nil {
		if token.Valid() {
			return token, nil
		}
		// we have an expired token, try and refresh if we can.
		if token.RefreshToken != "" {
			rts := c.client.TokenSource(ctx, token)
			t, err := rts.Token(ctx)
			// ignore errors here, just let it fail to a new token
			if err == nil {
				token = t
			}
		}
	}

	if token == nil {
		// if we get here cache and refresh failed, so fetch from upstream
		t, err := c.src.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching new token: %v", err)
		}
		token = t
	}

	if err := c.cache.Set(c.iss, c.aud, c.scopes, c.acrValues, token); err != nil {
		return nil, fmt.Errorf("updating cache: %v", err)
	}

	return token, nil
}
