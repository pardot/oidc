package memory

import (
	"context"
	"testing"

	"github.com/pardot/oidc/storage"
)

func TestStorage(t *testing.T) {
	ctx := context.Background()

	s := New()
	storage.Test(ctx, t, s)
}
