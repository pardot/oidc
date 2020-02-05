package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
	"github.com/pardot/oidc/core"
)

type metadata struct {
	Subject  string
	Userinfo map[string]interface{}
}

type session struct {
	Meta     *metadata
	SessData string
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

func (s *storage) NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *storage) GetSession(_ context.Context, sessionID string, into core.Session) (bool, error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := jsonpb.UnmarshalString(sess.SessData, into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *storage) PutSession(_ context.Context, sess core.Session) error {
	if sess.GetId() == "" {
		return fmt.Errorf("session has no ID")
	}
	sessjson, err := (&jsonpb.Marshaler{}).MarshalToString(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.GetId()] = &session{SessData: sessjson}
	return nil
}

func (s *storage) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}
