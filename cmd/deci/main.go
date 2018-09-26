package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"net/http"

	"crypto/rand"

	"github.com/gorilla/sessions"
	"github.com/heroku/deci"
	"github.com/heroku/deci/internal/server"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	sessionAuthenticationKeyBytesLength = 64
	sessionEncryptionKeyBytesLength     = 32
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		os.Exit(1)
	}
}

var cmd = cobra.Command{
	RunE: run,
}

var ( // flags
	addr                     string
	dcfg                     server.Config
	sessionAuthenticationKey string
	sessionEncryptionKey     string
)

func init() {
	cmd.Flags().StringVar(&addr, "addr", "localhost:5556", "Address to listen on")
	cmd.Flags().StringVar(&dcfg.Issuer, "issuer", "http://localhost:5556", "Issuer URL for OIDC provider")
	cmd.Flags().StringVar(&sessionAuthenticationKey, "session-auth-key", mustGenRandB64(64), "Session authentication key, 64-byte, base64-encoded")
	cmd.Flags().StringVar(&sessionEncryptionKey, "session-encrypt-key", mustGenRandB64(32), "Session encryption key, 32-byte, base64-encoded")
}

func run(cmd *cobra.Command, args []string) error {
	logger := logrus.New()

	sessionAuthenticationKey, err := base64.StdEncoding.DecodeString(sessionAuthenticationKey)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode session-auth-key")
	} else if len(sessionAuthenticationKey) != sessionAuthenticationKeyBytesLength {
		return fmt.Errorf("session-auth-key must be %d bytes of random data", sessionAuthenticationKeyBytesLength)
	}

	sessionEncryptionKey, err := base64.StdEncoding.DecodeString(sessionEncryptionKey)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode session-encrypt-key")
	} else if len(sessionEncryptionKey) != sessionEncryptionKeyBytesLength {
		return fmt.Errorf("session-encrypt-key must be %d bytes of random data", sessionEncryptionKeyBytesLength)
	}

	session := sessions.NewCookieStore(sessionAuthenticationKey, sessionEncryptionKey)

	// TODO - load config from somewhere
	a, err := deci.NewApp(logger, &server.Config{}, session)
	if err != nil {
		return errors.Wrap(err, "Error creating app")
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: a,
	}
	return srv.ListenAndServe()
}

func mustGenRandB64(len int) string {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Error fetching %d random bytes [%+v]", len, err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
