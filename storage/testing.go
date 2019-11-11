package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	jpbpb "github.com/golang/protobuf/jsonpb/jsonpb_test_proto"
)

func Test(ctx context.Context, t *testing.T, s Storage) {
	// Subtests must either clean up after themselves or use a unique keyspace
	t.Run("testNonexistingGet", func(t *testing.T) { testNonexistingGet(ctx, t, s) })
	t.Run("testSetGetDelete", func(t *testing.T) { testSetGetDelete(ctx, t, s) })
	t.Run("testVersioning", func(t *testing.T) { testVersioning(ctx, t, s) })
	t.Run("testExpiry", func(t *testing.T) { testExpiry(ctx, t, s) })
	t.Run("testList", func(t *testing.T) { testList(ctx, t, s) })
	t.Run("testDeleteConflict", func(t *testing.T) { testDeleteConflict(ctx, t, s) })
}

func testNonexistingGet(ctx context.Context, t *testing.T, s Storage) {
	msg := &jpbpb.Simple{}
	_, err := s.Get(ctx, "testNonexistingGet", "nothing", msg)
	if !IsNotFoundErr(err) {
		t.Errorf("Want: not found error, got %v", err)
	}
}

func testSetGetDelete(ctx context.Context, t *testing.T, s Storage) {
	h := "hello world"

	if _, err := s.Put(ctx, "testSetGetDelete", "setget", 0, &jpbpb.Simple{OString: &h}); err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	msg := new(jpbpb.Simple)
	msgver, err := s.Get(ctx, "testSetGetDelete", "setget", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	} else if msg.OString == nil || *msg.OString != h {
		t.Errorf("want: %s got: %v", h, msg.OString)
	}

	if err := s.Delete(ctx, "testSetGetDelete", "setget", msgver); err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	_, err = s.Get(ctx, "testSetGetDelete", "setget", msg)
	if !IsNotFoundErr(err) {
		t.Fatalf("Want: NotFoundError, got %v", err)
	}
}

func testVersioning(ctx context.Context, t *testing.T, s Storage) {
	ver1 := "version1"
	ver2 := "version2"

	_, err := s.Put(ctx, "testVersioning", "vers", 0, &jpbpb.Simple{OString: &ver1})
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	msg := new(jpbpb.Simple)
	vers, err := s.Get(ctx, "testVersioning", "vers", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	_, err = s.Put(ctx, "testVersioning", "vers", 0, &jpbpb.Simple{OString: &ver2})
	if !IsConflictErr(err) {
		t.Errorf("Want: conflict error, got %v", err)
	}

	_, err = s.Put(ctx, "testVersioning", "vers", vers, &jpbpb.Simple{OString: &ver2})
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	_, err = s.Get(ctx, "testVersioning", "vers", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	} else if *msg.OString != ver2 {
		t.Fatalf("Want: %s, got %s", ver2, *msg.OString)
	}
}

func testExpiry(ctx context.Context, t *testing.T, s Storage) {
	_, err := s.PutWithExpiry(ctx, "testExpiry", "exp", 0, &jpbpb.Simple{}, time.Now().Add(1*time.Second))
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	msg := new(jpbpb.Simple)
	_, err = s.Get(ctx, "testExpiry", "exp", msg)
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	time.Sleep(1 * time.Second)

	_, err = s.Get(ctx, "testExpiry", "exp", msg)
	if !IsNotFoundErr(err) {
		t.Errorf("Want: not found error, got %v", err)
	}

	_, err = s.Put(ctx, "testExpiry", "exp2", 0, &jpbpb.Simple{})
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}
}

func testList(ctx context.Context, t *testing.T, s Storage) {
	for i := 0; i < 10; i++ {
		if _, err := s.Put(ctx, "testList", fmt.Sprintf("item-%d", i), 0, &jpbpb.Simple{}); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := s.List(ctx, "testList")
	if err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}

	if len(keys) != 10 {
		t.Errorf("Want: 10 keys, got %d", len(keys))
	}
}

func testDeleteConflict(ctx context.Context, t *testing.T, s Storage) {
	version := 3

	for i := 0; i < version; i++ {
		if _, err := s.Put(ctx, "testDeleteConflict", "item", int64(i), &jpbpb.Simple{}); err != nil {
			t.Fatalf("Want: no error, got %v", err)
		}
	}

	if err := s.Delete(ctx, "testDeleteConflict", "item", 0); !IsConflictErr(err) {
		t.Fatalf("Want: conflict error, got %v", err)
	}

	if err := s.Delete(ctx, "testDeleteConflict", "item", int64(version)); err != nil {
		t.Fatalf("Want: no error, got %v", err)
	}
}
