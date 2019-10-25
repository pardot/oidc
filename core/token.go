package core

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	corestate "github.com/pardot/oidc/proto/deci/corestate/v1beta1"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenIDLen = 16
	tokenLen   = 48
)

var tokenEncoder = base64.RawURLEncoding

// token is an opaque, unique value that can be used as a code/access
// token/refresh token. it is designed for secure data storage (i.e leaking data
// won't give people usable data)
type token struct {
	id     []byte
	raw    []byte
	hashed []byte
}

// newToken generates a fresh token, from random data
func newToken() (*token, error) {
	b := make([]byte, tokenIDLen+tokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("error reading random data: %w", err)
	}
	bc, err := bcrypt.GenerateFromPassword(b[tokenIDLen:], bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	return &token{
		id:     b[0 : tokenIDLen-1],
		raw:    b[tokenIDLen:],
		hashed: bc,
	}, nil
}

// parseToken parses the string representation of a token.
func parseToken(t string) (*token, error) {
	sp := strings.SplitN(t, ".", 2)
	if len(sp) != 2 {
		return nil, fmt.Errorf("token is in an invalid format")
	}
	id, err := tokenEncoder.DecodeString(sp[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode key section of access token: %w", err)
	}
	raw, err := tokenEncoder.DecodeString(sp[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token section of access token: %w", err)
	}
	return &token{
		id:  id,
		raw: raw,
	}, nil
}

// String returns a string representation of the token, intended for presenting
// to the user. This is what the should be presented to the user.
func (t *token) String() string {
	return fmt.Sprintf(
		"%s.%s",
		tokenEncoder.EncodeToString(t.id),
		tokenEncoder.EncodeToString(t.raw),
	)
}

// ID returns an identifier for this token. This should be used for state
// storage. This is a partial value, after retrieving the full token information
// should be compared to see if they match
func (t *token) ID() string {
	return tokenEncoder.EncodeToString(t.id)
}

// Equal compares two tokens, and returns true if they match.
func (t *token) Equal(o *token) (bool, error) {
	if len(t.raw) > 0 && len(o.raw) > 0 {
		// both values contain the raw values. They are the same token if these
		// match
		return bytes.Equal(t.raw, o.raw), nil
	}

	// otherwise, compare one of the raw values to a hash. handle either
	// side being the hashed version
	var raw, hash []byte
	if len(t.hashed) > 0 {
		hash = t.hashed
		raw = o.raw
	} else if len(o.hashed) > 0 {
		hash = o.hashed
		raw = t.raw
	} else {
		// these two values are in no way comparable, so treat as an error
		return false, fmt.Errorf("tokens are not comparable - missing information required to validate")
	}

	err := bcrypt.CompareHashAndPassword(hash, raw)
	if err == nil {
		// no error in comparison, they match
		return true, nil
	} else if err == bcrypt.ErrMismatchedHashAndPassword {
		// they do not match, this isn't an error per se.
		return false, nil
	}
	return false, fmt.Errorf("failed comparing tokens: %w", err)
}

func (t *token) ToPB() (*corestate.Token, error) {
	if len(t.hashed) < 1 {
		var err error
		t.hashed, err = bcrypt.GenerateFromPassword(t.raw, bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed hashing token: %w", err)
		}
	}
	return &corestate.Token{
		Id:     t.id,
		Bcrypt: t.hashed,
	}, nil
}

func tokenFromPB(t *corestate.Token) *token {
	return &token{
		id:     t.Id,
		hashed: t.Bcrypt,
	}
}
