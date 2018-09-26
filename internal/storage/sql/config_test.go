package sql

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/heroku/deci/internal/storage"
	"github.com/heroku/deci/internal/storage/conformance"
)

func withTimeout(t time.Duration, f func()) {
	c := make(chan struct{})
	defer close(c)

	go func() {
		select {
		case <-c:
		case <-time.After(t):
			// Dump a stack trace of the program. Useful for debugging deadlocks.
			buf := make([]byte, 2<<20)
			fmt.Fprintf(os.Stderr, "%s\n", buf[:runtime.Stack(buf, true)])
			panic("test took too long")
		}
	}()

	f()
}

func cleanDB(c *conn) error {
	_, err := c.Exec(`
		delete from client;
		delete from auth_request;
		delete from auth_code;
		delete from refresh_token;
		delete from keys;
		delete from password;
		delete from webauth_association;
	`)
	return err
}

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

func getenv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

var postgresURL = flag.String("postgres-url", "", "URL of postgres DB to test against. Postgres test skipped if empty")

func TestPostgres(t *testing.T) {
	if *postgresURL == "" {
		t.Skip("-postgres-url not set, skipping")
	}

	// t.Fatal has a bad habbit of not actually printing the error
	fatal := func(i interface{}) {
		fmt.Fprintln(os.Stdout, i)
		t.Fatal(i)
	}

	newStorage := func() storage.Storage {
		stor, err := PostgresForURL(logger, *postgresURL)
		if err != nil {
			t.Fatalf("Error getting database instance [%+v]", err)
		}
		conn := stor.(*conn)
		if err := cleanDB(conn); err != nil {
			fatal(err)
		}
		return conn
	}
	withTimeout(time.Minute*1, func() {
		conformance.RunTests(t, newStorage)
	})
	withTimeout(time.Minute*1, func() {
		conformance.RunTransactionTests(t, newStorage)
	})
}
