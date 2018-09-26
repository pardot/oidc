package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"net/http"

	"github.com/gorilla/sessions"
	"github.com/heroku/deci"
	"github.com/heroku/deci/internal/server"
	"github.com/joeshaw/envdecode"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	sessionAuthenticationKeyBytesLength = 64
	sessionEncryptionKeyBytesLength     = 32
)

type config struct {
	Port int `env:"PORT,default=5556"`

	// SessionAuthenticationKey is a 64-byte, base64-encoded key used to
	// authenticate sessions
	SessionAuthenticationKey string `env:"SESSION_AUTHENTICATION_KEY,required"`
	// SessionEncryptionKey is a 32-byte, base64-encoded key used to encrypt
	// sessions
	SessionEncryptionKey string `env:"SESSION_ENCRYPTION_KEY,required"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		os.Exit(1)
	}
}

func run() error {
	logger := logrus.New()

	var cfg config
	if err := envdecode.StrictDecode(&cfg); err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	sessionAuthenticationKey, err := base64.StdEncoding.DecodeString(cfg.SessionAuthenticationKey)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode SESSION_AUTHENTICATION_KEY")
	} else if len(sessionAuthenticationKey) != sessionAuthenticationKeyBytesLength {
		return fmt.Errorf("SESSION_AUTHENTICATION_KEY must be %d bytes of random data", sessionAuthenticationKeyBytesLength)
	}

	sessionEncryptionKey, err := base64.StdEncoding.DecodeString(cfg.SessionEncryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode SESSION_ENCRYPTION_KEY")
	} else if len(sessionEncryptionKey) != sessionEncryptionKeyBytesLength {
		return fmt.Errorf("SESSION_ENCRYPTION_KEY must be %d bytes of random data", sessionEncryptionKeyBytesLength)
	}

	session := sessions.NewCookieStore(sessionAuthenticationKey, sessionEncryptionKey)
	// TODO - load config from somewhere
	a, err := deci.NewApp(logger, &server.Config{}, session)
	if err != nil {
		return errors.Wrap(err, "Error creating app")
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: a,
	}
	return srv.ListenAndServe()
}
