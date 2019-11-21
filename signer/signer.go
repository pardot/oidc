package signer

import (
	"context"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

func sign(_ context.Context, signingKey jose.SigningKey, data []byte) (signed []byte, err error) {
	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return nil, err
	}

	jws, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}

	ser, err := jws.CompactSerialize()
	return []byte(ser), err
}

func verifySignature(_ context.Context, verificationKeys []jose.JSONWebKey, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}

	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	for _, key := range verificationKeys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(key); err == nil {
				return payload, nil
			}
		}
	}

	return nil, errors.New("failed to verify id token signature")
}
