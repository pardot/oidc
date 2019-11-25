package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenLen = 48
)

// newToken generates a fresh token, from random data. The user and stored
// states are returned.
func newToken(sessID string, expires *timestamp.Timestamp) (*corev1beta1.UserToken, *corev1beta1.StoredToken, error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, fmt.Errorf("error reading random data: %w", err)
	}

	bc, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	ut := &corev1beta1.UserToken{
		Token:     b,
		SessionId: sessID,
	}

	st := &corev1beta1.StoredToken{
		Bcrypted:  bc,
		ExpiresAt: expires,
	}

	return ut, st, nil
}

// tokensMatch compares a deserialized user token, and it's corresponding stored
// token. if the user token value hashes to the same value on the server.
func tokensMatch(user *corev1beta1.UserToken, stored *corev1beta1.StoredToken) (bool, error) {
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
func marshalToken(user *corev1beta1.UserToken) (string, error) {
	b, err := proto.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal user token to proto: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func unmarshalToken(tok string) (*corev1beta1.UserToken, error) {
	b, err := base64.RawStdEncoding.DecodeString(tok)
	if err != nil {
		return nil, fmt.Errorf("base64 decode of token failed: %w", err)
	}
	ut := &corev1beta1.UserToken{}
	if err := proto.Unmarshal(b, ut); err != nil {
		return nil, fmt.Errorf("proto decoding of token failed: %w", err)
	}
	return ut, err
}
