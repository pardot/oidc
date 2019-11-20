package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	corestate "github.com/pardot/oidc/proto/deci/corestate/v1beta1"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenIDLen = 16
	tokenLen   = 48
)

// newToken generates a fresh token, from random data. The user and stored
// states are returned.
func newToken(sessID string, tokType corestate.TokenType, expires time.Time) (*corestate.UserToken, *corestate.StoredToken, error) {
	b := make([]byte, tokenIDLen+tokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, fmt.Errorf("error reading random data: %w", err)
	}
	tokenID := base64.RawStdEncoding.EncodeToString(b[0 : tokenIDLen-1])
	rawToken := b[tokenIDLen:]

	bc, err := bcrypt.GenerateFromPassword(b[tokenIDLen:], bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	exp, err := ptypes.TimestampProto(expires)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert expiry to proto: %w", err)
	}

	ut := &corestate.UserToken{
		TokenType: tokType,
		TokenId:   tokenID,
		Token:     rawToken,
		SessionId: sessID,
	}

	st := &corestate.StoredToken{
		TokenType: tokType,
		Bcrypted:  bc,
		ExpiresAt: exp,
	}

	return ut, st, nil
}

// tokensMatch compares a deserialized user token, and it's corresponding stored
// token. if the user token value hashes to the same value on the server.
func tokensMatch(user *corestate.UserToken, stored *corestate.StoredToken) (bool, error) {
	err := bcrypt.CompareHashAndPassword(stored.Bcrypted, user.Token)
	if err == nil {
		// no error in comparison, they match
		return true, nil
	} else if err == bcrypt.ErrMismatchedHashAndPassword {
		// they do not match, this isn't an error per se.
		return false, nil
	}
	return false, fmt.Errorf("failed comparing tokens: %w", err)
}

// marshalToken returns a user-friendly version of the token. This is the base64
// serialized marshaled proto
func marshalToken(user *corestate.UserToken) (string, error) {
	b, err := proto.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal user token to proto: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func unmarshalToken(tok string) (*corestate.UserToken, error) {
	b, err := base64.RawStdEncoding.DecodeString(tok)
	if err != nil {
		return nil, fmt.Errorf("base64 decode of token failed: %w", err)
	}
	ut := &corestate.UserToken{}
	if err := proto.Unmarshal(b, ut); err != nil {
		return nil, fmt.Errorf("proto decoding of token failed: %w", err)
	}
	return ut, err
}
