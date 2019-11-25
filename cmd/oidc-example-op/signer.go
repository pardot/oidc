package main

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pardot/oidc/signer"
	"gopkg.in/square/go-jose.v2"
)

func mustInitSigner() *signer.StaticSigner {
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		panic(err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
		Key:   key,
		KeyID: "testkey",
	}}

	verificationKeys := []jose.JSONWebKey{
		{
			Key:       key.Public(),
			KeyID:     "testkey",
			Algorithm: "RS256",
			Use:       "sig",
		},
	}

	return signer.NewStatic(signingKey, verificationKeys)

}
