package sql

import (
	"context"
	"database/sql"
	"flag"
	"testing"

	"github.com/pardot/deci/storage"
	_ "github.com/lib/pq"
)

var (
	dbURL = flag.String("db-url", "", "Database URL")
)

func init() {
	flag.Parse()
}

func TestStorage(t *testing.T) {
	if *dbURL == "" {
		t.Skip("-db-url not set, skipping")
	}

	ctx, s := setup(t)
	storage.Test(ctx, t, s)
}

func setup(t *testing.T) (ctx context.Context, s *Storage) {
	ctx = context.Background()

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"migrations", "values"} {
		if _, err := db.Exec(`drop table if exists ` + table); err != nil {
			t.Fatal(err)
		}
	}

	s, err = New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	return ctx, s
}
