package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	"github.com/heroku/deci/internal/connector/salesforce"

	"net/http"

	"crypto/rand"

	"github.com/gorilla/sessions"
	"github.com/heroku/deci"
	"github.com/heroku/deci/internal/server"
	"github.com/heroku/deci/internal/storage"
	"github.com/heroku/deci/internal/storage/sql"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
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
	scfg                     server.Config
	conncfg                  salesforce.Config
	sessionAuthenticationKey string
	sessionEncryptionKey     string
	dbURL                    string
	staticClientPath         string
)

func init() {
	cmd.Flags().StringVar(&addr, "addr", "localhost:5556", "Address to listen on")
	cmd.Flags().StringVar(&scfg.Issuer, "issuer", "http://localhost:5556", "Issuer URL for OIDC provider")
	cmd.Flags().StringVar(&conncfg.ClientID, "upstream-client-id", "", "Client ID for upstream connector")
	cmd.MarkFlagRequired("upstream-client-id")
	cmd.Flags().StringVar(&conncfg.ClientSecret, "upstream-client-secret", "", "Client Secret for upstream connector")
	cmd.MarkFlagRequired("upstream-client-secret")
	cmd.Flags().StringVar(&conncfg.Issuer, "upstream-issuer", "", "Issuer for upstream provider")
	cmd.MarkFlagRequired("upstream-issuer")
	cmd.Flags().StringVar(&conncfg.RedirectURI, "upstream-redirect", "", "Redirect URI for upstream provider")
	cmd.MarkFlagRequired("upstream-redirect")
	cmd.Flags().StringVar(&sessionAuthenticationKey, "session-auth-key", mustGenRandB64(64), "Session authentication key, 64-byte, base64-encoded")
	cmd.Flags().StringVar(&sessionEncryptionKey, "session-encrypt-key", mustGenRandB64(32), "Session encryption key, 32-byte, base64-encoded")
	cmd.Flags().StringVar(&dbURL, "database", defaultDBUrl(), "URL to postgres database for persistence")
	cmd.Flags().StringVar(&staticClientPath, "static-clients", "config/static-clients.yaml", "File containing static client mappings")
	cmd.Flags().StringVar(&conncfg.GroupFile, "group-mappings", "config/local-mappings.yaml", "File mapping salesforce IDs to groups")
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

	// Configure OIDC server

	scfg.Logger = logger
	scfg.PrometheusRegistry = prometheus.NewRegistry() // TODO: Actually register stuff to this
	scfg.AuthPrefix = "/auth"                          // where we want incoming requests from clients to land

	store, err := sql.PostgresForURL(logger, dbURL)
	if err != nil {
		return errors.Wrap(err, "failed to configure storage")
	}

	if staticClientPath != "" {
		cb, err := ioutil.ReadFile(staticClientPath)
		if err != nil {
			return errors.Wrapf(err, "Error reading static client config from %s", staticClientPath)
		}
		clients := []storage.Client{}
		if err := yaml.Unmarshal(cb, &clients); err != nil {
			return errors.Wrapf(err, "Error unmarshaling yaml from %s", staticClientPath)
		}
		store = storage.WithStaticClients(store, clients)
	}

	scfg.Storage = store

	connector, err := conncfg.Open("upstream", logger)
	if err != nil {
		return errors.Wrap(err, "Error opening upstream connector")
	}
	scfg.Connector = connector

	server, err := server.NewServer(context.Background(), &scfg)
	if err != nil {
		return err
	}

	session := sessions.NewCookieStore(sessionAuthenticationKey, sessionEncryptionKey)

	// TODO - load config from somewhere
	a, err := deci.NewApp(logger, connector, server, session)
	if err != nil {
		return errors.Wrap(err, "Error creating app")
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: a,
	}
	logger.WithField("addr", addr).Info("starting")
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

func defaultDBUrl() string {
	// socket stuff seems weird on mac, but network is on by default in brew
	if runtime.GOOS == "darwin" {
		return "postgres://127.0.0.1/deci?sslmode=disable"
	}
	return "postgres:///deci"
}
