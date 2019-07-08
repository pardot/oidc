package disk

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	jpbpb "github.com/golang/protobuf/jsonpb/jsonpb_test_proto"
	"github.com/heroku/deci/storage"
)

func TestNonexistingGet(t *testing.T) {
	ctx, s, deferred := setup(t)
	defer deferred()

	msg := &jpbpb.Simple{}
	_, err := s.Get(ctx, "nothing", "nothing", msg)
	if !storage.IsNotFoundErr(err) {
		t.Errorf("Want: not found error, got %v", err)
	}
}

func TestSetGet(t *testing.T) {
	ctx, s, deferred := setup(t)
	defer deferred()

	h := "hellp"

	msg := &jpbpb.Simple{
		OString: &h,
	}

	err := s.Put(ctx, "test", "setget", "", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	msg = &jpbpb.Simple{}
	_, err = s.Get(ctx, "test", "setget", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	if msg.OString == nil || *msg.OString != h {
		t.Errorf("want: %s got: %v", h, msg.OString)
	}
}

func TestVersioning(t *testing.T) {
	ctx, s, deferred := setup(t)
	defer deferred()

	msg := &jpbpb.Simple{}

	err := s.Put(ctx, "test", "vers", "", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	vers, err := s.Get(ctx, "test", "vers", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	err = s.Put(ctx, "test", "vers", "", msg)
	if !storage.IsConflictErr(err) {
		t.Errorf("Want: conflict error, got %v", err)
	}

	err = s.Put(ctx, "test", "vers", vers, msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	ctx, s, deferred := setup(t)
	defer deferred()

	defer func() { s.now = time.Now }()

	msg := &jpbpb.Simple{}

	err := s.PutWithExpiry(ctx, "test", "exp", "", msg, time.Now().Add(1*time.Minute))
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	_, err = s.Get(ctx, "test", "exp", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	// pretend we're a day in the future now
	s.now = func() time.Time { return time.Now().Add(24 * time.Hour) }

	_, err = s.Get(ctx, "test", "exp", msg)
	if !storage.IsNotFoundErr(err) {
		t.Errorf("Want: not found error, got %v", err)
	}
}

func TestList(t *testing.T) {
	ctx, s, deferred := setup(t)
	defer deferred()

	msg := &jpbpb.Simple{}

	for i := 0; i < 10; i++ {
		if err := s.Put(ctx, "testlist", fmt.Sprintf("item-%d", i), "", msg); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := s.List(ctx, "testlist")
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	if len(keys) != 10 {
		t.Fatalf("Want: 10 keys, got %d", len(keys))
	}
}

func setup(t *testing.T) (ctx context.Context, s *Storage, deferred func()) {
	t.Helper()
	ctx = context.Background()

	dir, err := ioutil.TempDir("", "disk-storage-test")
	if err != nil {
		t.Fatal(err)
	}

	deferred = func() {
		_ = os.RemoveAll(dir)
	}

	s, err = New(dir+"disktest.db", 0644)
	if err != nil {
		t.Fatal(err)
	}

	return ctx, s, deferred
}
