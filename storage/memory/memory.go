package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
)

// Storage is an in-memory implementation of storage.Storage. It should only be
// used for testing or similar. All data will be lost when the process ends.
type Storage struct {
	sync.Mutex
	m map[string]map[string]*record
}

type record struct {
	Version int64
	Data    []byte
	Expires *time.Time
}

func New() *Storage {
	return &Storage{
		m: make(map[string]map[string]*record),
	}
}

func (s *Storage) Get(ctx context.Context, keyspace, key string, into proto.Message) (version int64, err error) {
	s.Lock()
	defer s.Unlock()

	mm, ok := s.m[keyspace]
	if !ok {
		return 0, &errNotFound{errors.New("keyspace not found")}
	}

	r, ok := mm[key]
	if !ok {
		return 0, &errNotFound{errors.New("key not found")}
	}

	if r.Expires != nil && time.Now().After(*r.Expires) {
		return 0, &errNotFound{errors.New("key not found")}
	}

	if err := proto.Unmarshal(r.Data, into); err != nil {
		return 0, err
	}

	return r.Version, nil
}

func (s *Storage) Put(ctx context.Context, keyspace, key string, version int64, obj proto.Message) (newVersion int64, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, nil)
}

func (s *Storage) PutWithExpiry(ctx context.Context, keyspace, key string, version int64, obj proto.Message, expires time.Time) (newVersion int64, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, &expires)
}

func (s *Storage) putWithOptionalExpiry(_ context.Context, keyspace, key string, version int64, obj proto.Message, expires *time.Time) (newVersion int64, err error) {
	s.Lock()
	defer s.Unlock()

	mm, ok := s.m[keyspace]
	if !ok {
		mm = make(map[string]*record)
		s.m[keyspace] = mm
	}

	var oldversion int64
	r, ok := mm[key]
	if ok {
		oldversion = r.Version

		if oldversion != version && (r.Expires == nil || time.Now().Before(*r.Expires)) {
			return 0, &errConflict{errors.New("conflict")}
		}
	}

	data, err := proto.Marshal(obj)
	if err != nil {
		return 0, err
	}

	r = &record{
		Version: version + 1,
		Data:    data,
		Expires: expires,
	}
	mm[key] = r

	return r.Version, nil
}

func (s *Storage) List(ctx context.Context, keyspace string) (keys []string, err error) {
	s.Lock()
	defer s.Unlock()

	mm, ok := s.m[keyspace]
	if !ok {
		return []string{}, nil
	}

	keys = make([]string, 0, len(mm))
	for k, r := range mm {
		if r.Expires != nil && time.Now().After(*r.Expires) {
			continue
		}

		keys = append(keys, k)
	}

	return keys, nil
}

func (s *Storage) Delete(ctx context.Context, keyspace, key string, version int64) error {
	s.Lock()
	defer s.Unlock()

	mm, ok := s.m[keyspace]
	if !ok {
		return nil
	}

	r, ok := mm[key]
	if !ok {
		return &errNotFound{fmt.Errorf("%s/%s not found", keyspace, key)}
	}

	if r.Version != version {
		return &errConflict{fmt.Errorf("%s/%s version conflict, want to delete version %d but current version is %d", keyspace, key, version, r.Version)}
	}

	delete(mm, key)
	return nil
}
