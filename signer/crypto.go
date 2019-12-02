package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
)

type CryptoSigner struct {
	signer  jose.Signer
	pubKeys *jose.JSONWebKeySet
	keyID   string

	alg jose.SignatureAlgorithm
}

// NewFromCrypto returns a new Signer, that wraps a crypto.Signer for the actual
// signing/public key options. keyID is used to set the `kid`
// (https://tools.ietf.org/html/rfc7517#section-4.5) field for the returned JWK,
// as there's no good way to infer it from the given signer.
func NewFromCrypto(signer crypto.Signer, keyID string) (*CryptoSigner, error) {
	c := &CryptoSigner{
		keyID: keyID,
	}

	// TODO - what's a better way to be more specific with this.
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		c.alg = jose.ES256
	case *rsa.PublicKey:
		c.alg = jose.RS256
	default:
		return nil, fmt.Errorf("unsupported key type: %T", signer.Public())
	}

	opaqueSigner := cryptosigner.Opaque(signer)

	s, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: c.alg,
			Key: &jose.JSONWebKey{
				Algorithm: string(c.alg),
				Key:       opaqueSigner,
				KeyID:     keyID,
				Use:       "sig",
			},
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	c.signer = s

	c.pubKeys = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       signer.Public(),
				KeyID:     keyID,
				Algorithm: string(c.alg),
			},
		},
	}

	return c, nil
}

// PublicKeys returns the public key set this signer is valid for
func (c *CryptoSigner) PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error) {
	return c.pubKeys, nil
}

// SignerAlg returns the algorithm this signer uses
func (c *CryptoSigner) SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error) {
	return c.alg, nil
}

// Sign the provided data
func (c *CryptoSigner) Sign(ctx context.Context, data []byte) (signed []byte, err error) {
	jws, err := c.signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	ser, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}

	return []byte(ser), nil
}

// VerifySignature verifies the signature given token against the current signers
func (c *CryptoSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	var found bool
	for _, sig := range jws.Signatures {
		if sig.Header.KeyID == c.keyID {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("key not found in jwt headers")
	}

	payload, err = jws.Verify(c.pubKeys.Keys[0].Public())
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %w", err)
	}

	return payload, nil
}
