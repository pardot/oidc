package signer

import (
	"context"

	jose "github.com/go-jose/go-jose/v3"
)

// StaticSigner uses a fixed set of keys to manage signing operations
type StaticSigner struct {
	signingKey       jose.SigningKey
	verificationKeys []jose.JSONWebKey
}

// NewStatic returns a StaticSigner with the provided keys
func NewStatic(signingKey jose.SigningKey, verificationKeys []jose.JSONWebKey) *StaticSigner {
	return &StaticSigner{
		signingKey:       signingKey,
		verificationKeys: verificationKeys,
	}
}

// PublicKeys returns a keyset of all valid signer public keys considered
// valid for signed tokens
func (s *StaticSigner) PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error) {
	return &jose.JSONWebKeySet{
		Keys: s.verificationKeys,
	}, nil
}

// SignerAlg returns the algorithm the signer uses
func (s *StaticSigner) SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error) {
	return s.signingKey.Algorithm, nil
}

// Sign the provided data
func (s *StaticSigner) Sign(ctx context.Context, data []byte) (signed []byte, err error) {
	return sign(ctx, s.signingKey, data)
}

// VerifySignature verifies the signature given token against the current signers
func (s *StaticSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	return verifySignature(ctx, s.verificationKeys, jwt)
}
