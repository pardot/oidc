package core

import (
	"fmt"
	"time"

	structpb "github.com/golang/protobuf/ptypes/struct"
)

type Claims map[string]interface{}

// NewClaims creates a new Claims with the required claims set.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func NewClaims(iss, sub, aud string, exp, iat time.Time) Claims {
	return map[string]interface{}{
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"exp": exp.Unix(),
		"iat": iat.Unix(),
	}
}

func claimsFromProto(claims *structpb.Struct) (Claims, error) {
	ret, err := pbstructToGo(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proto struct to claims: %w", err)
	}
	return Claims(ret), nil
}

func (c Claims) toProto() (*structpb.Struct, error) { //nolint:unused
	pb, err := goToPBStruct(c)
	if err != nil {
		return nil, fmt.Errorf("failed to convert claims to proto struct: %w", err)
	}
	return pb, nil
}
