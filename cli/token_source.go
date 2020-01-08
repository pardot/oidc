package cli

import (
	"context"

	"golang.org/x/oauth2"
)

// OIDCTokenSource fetches OIDC tokens. The returned oauth2.Token is expected
// to have Extra("id_token") populated with an OIDC ID token.
type OIDCTokenSource interface {
	// Token returns a token or an error.
	// The returned Token must not be modified
	Token(ctx context.Context) (*oauth2.Token, error)
}
