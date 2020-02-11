package client

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pardot/oidc/discovery"
	"github.com/pardot/oidc/idtoken"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Verifier struct {
	md *discovery.ProviderMetadata
	ks KeySource
}

func DiscoverVerifier(ctx context.Context, issuer string) (*Verifier, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	return &Verifier{
		md: cl.Metadata(),
		ks: cl,
	}, nil
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (v *Verifier) VerifyRaw(ctx context.Context, audience string, raw string, opts ...VerifyOpt) (*idtoken.Claims, error) {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("failed parsing raw: %v", err)
	}

	var kid string
	for _, h := range tok.Headers {
		if h.KeyID != "" {
			kid = h.KeyID
			break
		}
	}
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}

	key, err := v.ks.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("fetching key %s: %v", kid, err)
	}

	// parse it into the library claims so we can use their verification code
	cl := jwt.Claims{}
	if err := tok.Claims(key, &cl); err != nil {
		return nil, fmt.Errorf("verifying token claims: %v", err)
	}

	log.Printf("validate %s against issuer: %s", raw, v.md.Issuer)

	if err := cl.Validate(jwt.Expected{
		Issuer:   v.md.Issuer,
		Audience: jwt.Audience([]string{audience}),
		Time:     time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("claim validation: %v", err)
	}

	// now parse it in to our type to return
	idt := idtoken.Claims{}
	if err := tok.Claims(key, &idt); err != nil {
		return nil, fmt.Errorf("verifying token claims: %v", err)
	}

	return &idt, nil
}
