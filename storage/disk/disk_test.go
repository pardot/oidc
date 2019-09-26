package disk

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/pardot/deci/storage"
)

func TestStorage(t *testing.T) {
	ctx, s, cleanup := setup(t)
	defer cleanup()

	storage.Test(ctx, t, s)
}

func setup(t *testing.T) (ctx context.Context, s *Storage, cleanup func()) {
	t.Helper()
	ctx = context.Background()

	dir, err := ioutil.TempDir("", "disk-storage-test")
	if err != nil {
		t.Fatal(err)
	}

	cleanup = func() {
		_ = os.RemoveAll(dir)
	}

	s, err = New(dir+"disktest.db", 0644)
	if err != nil {
		t.Fatal(err)
	}

	return ctx, s, cleanup
}
