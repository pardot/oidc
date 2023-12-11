package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	jose "github.com/go-jose/go-jose/v3"
)

type signer interface {
	PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error)
	SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error)
	Sign(_ context.Context, data []byte) (signed []byte, err error)
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

func TestSigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, otc := range []struct {
		name   string
		signer func(t *testing.T) signer
	}{
		{
			name: "static",
			signer: func(t *testing.T) signer {
				t.Helper()

				key := mustGenRSAKey(512)

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

				return NewStatic(signingKey, verificationKeys)
			},
		},
	} {
		t.Run(otc.name, func(t *testing.T) {
			signer := otc.signer(t)

			tests := []struct {
				name           string
				tokenGenerator func() (jwt string, err error)
				wantErr        bool
			}{
				{
					name: "valid token",
					tokenGenerator: func() (string, error) {
						s, err := signer.Sign(ctx, []byte("payload"))
						return string(s), err
					},
					wantErr: false,
				},
				{
					name: "token signed by different key",
					tokenGenerator: func() (string, error) {
						key, err := rsa.GenerateKey(rand.Reader, 2048)
						if err != nil {
							return "", err
						}

						signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{
							Key:   key,
							KeyID: "badkey",
						}}, nil)
						if err != nil {
							return "", err
						}

						jws, err := signer.Sign([]byte("payload"))
						if err != nil {
							return "", err
						}

						return jws.CompactSerialize()
					},
					wantErr: true,
				},
			}

			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					jwt, err := tc.tokenGenerator()
					if err != nil {
						t.Fatal(err)
					}

					jws, err := jose.ParseSigned(string(jwt))
					if err != nil {
						t.Fatal(err)
					}

					if len(jws.Signatures) != 1 {
						t.Fatalf("want one signature, got %d", len(jws.Signatures))
					}

					if jws.Signatures[0].Header.KeyID == "" {
						t.Error("Signed token has empty Key ID")
					}

					_, err = signer.VerifySignature(context.Background(), jwt)
					if (err != nil && !tc.wantErr) || (err == nil && tc.wantErr) {
						t.Fatalf("wantErr = %v, but got err = %v", tc.wantErr, err)
					}
				})
			}
		})
	}
}

func mustGenRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}
