package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
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

				signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: testKey}

				verificationKeys := []jose.JSONWebKey{
					{
						Key:       testKey.Public(),
						KeyID:     "testkey",
						Algorithm: "RS256",
						Use:       "sig",
					},
				}

				return NewStatic(signingKey, verificationKeys)
			},
		},
		{
			name: "rotating",
			signer: func(t *testing.T) signer {
				t.Helper()

				s, deferred := newStorage(t)
				defer deferred()

				r := &RotatingSigner{
					storage:  s,
					strategy: DefaultRotationStrategy(time.Second*1, time.Second*5),
					now:      time.Now,
					logger:   &logrus.Logger{Out: ioutil.Discard},
				}
				_ = r.Start(ctx)
				return r
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

						signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
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

					_, err = signer.VerifySignature(context.Background(), jwt)
					if (err != nil && !tc.wantErr) || (err == nil && tc.wantErr) {
						t.Fatalf("wantErr = %v, but got err = %v", tc.wantErr, err)
					}
				})
			}
		})
	}
}

func mustLoad(s string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		panic("no pem data found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

var testKey = mustLoad(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArmoiX5G36MKPiVGS1sicruEaGRrbhPbIKOf97aGGQRjXVngo
Knwd2L4T9CRyABgQm3tLHHcT5crODoy46wX2g9onTZWViWWuhJ5wxXNmUbCAPWHb
j9SunW53WuLYZ/IJLNZt5XYCAFPjAakWp8uMuuDwWo5EyFaw85X3FSMhVmmaYDd0
cn+1H4+NS/52wX7tWmyvGUNJ8lzjFAnnOtBJByvkyIC7HDphkLQV4j//sMNY1mPX
HbsYgFv2J/LIJtkjdYO2UoDhZG3Gvj16fMy2JE2owA8IX4/s+XAmA2PiTfd0J5b4
drAKEcdDl83G6L3depEkTkfvp0ZLsh9xupAvIwIDAQABAoIBABKGgWonPyKA7+AF
AxS/MC0/CZebC6/+ylnV8lm4K1tkuRKdJp8EmeL4pYPsDxPFepYZLWwzlbB1rxdK
iSWld36fwEb0WXLDkxrQ/Wdrj3Wjyqs6ZqjLTVS5dAH6UEQSKDlT+U5DD4lbX6RA
goCGFUeQNtdXfyTMWHU2+4yKM7NKzUpczFky+0d10Mg0ANj3/4IILdr3hqkmMSI9
1TB9ksWBXJxt3nGxAjzSFihQFUlc231cey/HhYbvAX5fN0xhLxOk88adDcdXE7br
3Ser1q6XaaFQSMj4oi1+h3RAT9MUjJ6johEqjw0PbEZtOqXvA1x5vfFdei6SqgKn
Am3BspkCgYEA2lIiKEkT/Je6ZH4Omhv9atbGoBdETAstL3FnNQjkyVau9f6bxQkl
4/sz985JpaiasORQBiTGY8JDT/hXjROkut91agi2Vafhr29L/mto7KZglfDsT4b2
9z/EZH8wHw7eYhvdoBbMbqNDSI8RrGa4mpLpuN+E0wsFTzSZEL+QMQUCgYEAzIQh
xnreQvDAhNradMqLmxRpayn1ORaPReD4/off+mi7hZRLKtP0iNgEVEWHJ6HEqqi1
r38XAc8ap/lfOVMar2MLyCFOhYspdHZ+TGLZfr8gg/Fzeq9IRGKYadmIKVwjMeyH
REPqg1tyrvMOE0HI5oqkko8JTDJ0OyVC0Vc6+AcCgYAqCzkywugLc/jcU35iZVOH
WLdFq1Vmw5w/D7rNdtoAgCYPj6nV5y4Z2o2mgl6ifXbU7BMRK9Hc8lNeOjg6HfdS
WahV9DmRA1SuIWPkKjE5qczd81i+9AHpmakrpWbSBF4FTNKAewOBpwVVGuBPcDTK
59IE3V7J+cxa9YkotYuCNQKBgCwGla7AbHBEm2z+H+DcaUktD7R+B8gOTzFfyLoi
Tdj+CsAquDO0BQQgXG43uWySql+CifoJhc5h4v8d853HggsXa0XdxaWB256yk2Wm
MePTCRDePVm/ufLetqiyp1kf+IOaw1Oyux0j5oA62mDS3Iikd+EE4Z+BjPvefY/L
E2qpAoGAZo5Wwwk7q8b1n9n/ACh4LpE+QgbFdlJxlfFLJCKstl37atzS8UewOSZj
FDWV28nTP9sqbtsmU8Tem2jzMvZ7C/Q0AuDoKELFUpux8shm8wfIhyaPnXUGZoAZ
Np4vUwMSYV5mopESLWOg3loBxKyLGFtgGKVCjGiQvy6zISQ4fQo=
-----END RSA PRIVATE KEY-----`)
