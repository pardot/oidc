package signer

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	storagepb "github.com/heroku/deci/proto/deci/storage/v1beta1"
	"github.com/heroku/deci/storage"
	"github.com/heroku/deci/storage/disk"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

func signingKeyID(t *testing.T, s storage.Storage) string {
	keys := &storagepb.Keys{}
	_, err := s.Get(context.TODO(), keysPrefix, keysKey, keys)
	if err != nil {
		t.Fatal(err)
	}
	swk := jose.JSONWebKey{}
	if err := json.Unmarshal(keys.SigningKey, &swk); err != nil {
		t.Fatal(err)
	}
	return swk.KeyID
}

func verificationKeyIDs(t *testing.T, s storage.Storage) (ids []string) {
	keys := &storagepb.Keys{}
	_, err := s.Get(context.TODO(), keysPrefix, keysKey, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys.VerificationKeys {
		vk := jose.JSONWebKey{}
		if err := json.Unmarshal(key.PublicKey, &vk); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, vk.KeyID)
	}
	return ids
}

// slicesEq compare two string slices without modifying the ordering
// of the slices.
func slicesEq(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	cp := func(s []string) []string {
		c := make([]string, len(s))
		copy(c, s)
		return c
	}

	cp1 := cp(s1)
	cp2 := cp(s2)
	sort.Strings(cp1)
	sort.Strings(cp2)

	for i, el := range cp1 {
		if el != cp2[i] {
			return false
		}
	}
	return true
}

func TestKeyRotater(t *testing.T) {
	now := time.Now()

	delta := time.Millisecond
	rotationFrequency := time.Second * 5
	validFor := time.Second * 21

	// Only the last 5 verification keys are expected to be kept around.
	maxVerificationKeys := 5

	l := &logrus.Logger{
		Out:       os.Stderr,
		Formatter: &logrus.TextFormatter{DisableColors: true},
		Level:     logrus.DebugLevel,
	}

	s, deferred := newStorage(t)
	defer deferred()

	r := &RotatingSigner{
		storage:  s,
		strategy: DefaultRotationStrategy(rotationFrequency, validFor),
		now:      func() time.Time { return now },
		logger:   l,
	}

	var expVerificationKeys []string

	for i := 0; i < 10; i++ {
		now = now.Add(rotationFrequency + delta)
		if err := r.rotate(); err != nil {
			t.Fatal(err)
		}

		got := verificationKeyIDs(t, r.storage)

		if !slicesEq(expVerificationKeys, got) {
			t.Errorf("after %d rotation, expected verification keys %q, got %q", i+1, expVerificationKeys, got)
		}

		expVerificationKeys = append(expVerificationKeys, signingKeyID(t, r.storage))
		if n := len(expVerificationKeys); n > maxVerificationKeys {
			expVerificationKeys = expVerificationKeys[n-maxVerificationKeys:]
		}
	}
}

// New returns an in memory
func newStorage(t *testing.T) (storage.Storage, func()) {
	t.Helper()

	dir, err := ioutil.TempDir("", "signer-test")
	if err != nil {
		t.Fatal(err)
	}

	deferred := func() {
		_ = os.RemoveAll(dir)
	}

	s, err := disk.New(filepath.Join(dir, "test.db"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	return s, deferred
}
