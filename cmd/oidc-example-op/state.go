package main

import (
	"context"
	"fmt"

	"github.com/pardot/oidc/core"
	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
)

type metadata struct {
	Subject  string
	Userinfo map[string]interface{}
}

type session struct {
	Meta    *metadata
	Session *corev1beta1.Session
}

type storage struct {
	// sessions maps session objects by the core session ID
	sessions map[string]*session
}

func newStubSMGR() *storage {
	return &storage{
		sessions: map[string]*session{},
	}
}

func (s *storage) GetSession(_ context.Context, sessionID string) (core.Session, error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil
	}
	return sess.Session, nil
}

func (s *storage) PutSession(_ context.Context, sess core.Session) error {
	if sess.GetId() == "" {
		return fmt.Errorf("session has no ID")
	}
	csess := sess.(*corev1beta1.Session)
	s.sessions[sess.GetId()] = &session{Session: csess}
	return nil
}

func (s *storage) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}
