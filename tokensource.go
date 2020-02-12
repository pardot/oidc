package oidc

import "context"

// TokenSource fetches OIDC tokens.
type TokenSource interface {
	// Token returns a token or an error.
	// The returned Token must not be modified
	Token(ctx context.Context) (*Token, error)
}
