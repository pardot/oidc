package sql

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/pardot/deci/storage"
)

func TestStorage(t *testing.T) {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		t.Skip("DB_URL not set, skipping")
	}

	ctx, s := setup(t, dbURL)
	storage.Test(ctx, t, s)
}

func setup(t *testing.T, dbURL string) (ctx context.Context, s *Storage) {
	ctx = context.Background()

	db, err := sql.Open("postgres", dbURL)
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
