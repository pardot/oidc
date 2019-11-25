package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
	"github.com/pardot/oidc/signer"
	"gopkg.in/square/go-jose.v2"
)

// contains helpers used by multiple tests

type csClient struct {
	Secret      string
	RedirectURI string
}

type stubCS struct {
	validClients map[string]csClient
}

func (s *stubCS) IsValidClientID(clientID string) (ok bool, err error) {
	_, ok = s.validClients[clientID]
	return ok, nil
}

func (s *stubCS) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *stubCS) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, ok := s.validClients[clientID]
	return ok && clientSecret == cl.Secret, nil
}

func (s *stubCS) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, ok := s.validClients[clientID]
	return ok && redirectURI == cl.RedirectURI, nil
}

type stubSMGR struct {
	// sessions maps session objects by their ID
	sessions map[string]*corev1beta1.Session
}

func newStubSMGR() *stubSMGR {
	return &stubSMGR{
		sessions: map[string]*corev1beta1.Session{},
	}
}

func (s *stubSMGR) GetSession(_ context.Context, sessionID string) (Session, error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil
	}
	return sess, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess Session) error {
	if sess.GetId() == "" {
		return fmt.Errorf("session has no ID")
	}
	csess := sess.(*corev1beta1.Session)
	s.sessions[sess.GetId()] = csess
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

var testSigner = func() Signer {
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

	return signer.NewStatic(signingKey, verificationKeys)
}()

func mustGenRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}
