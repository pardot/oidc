package oidc

import (
	"context"
	"fmt"

	"gopkg.in/square/go-jose.v2"
)

var _ KeySource = (*StaticKeysource)(nil)

type StaticKeysource struct {
	keys jose.JSONWebKeySet
}

func NewStaticKeysource(keys jose.JSONWebKeySet) *StaticKeysource {
	return &StaticKeysource{
		keys: keys,
	}
}

func (s *StaticKeysource) GetKey(_ context.Context, kid string) (*jose.JSONWebKey, error) {
	for _, k := range s.keys.Keys {
		if k.KeyID == kid {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("key %s not found", kid)
}
