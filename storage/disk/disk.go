package disk

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	bolt "go.etcd.io/bbolt"
)

type record struct {
	Version int64
	Data    []byte
	Expires *time.Time
}

func (r *record) encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(r)
	return buf.Bytes(), err
}

func decodeRecord(data []byte) (*record, error) {
	var r *record
	buf := bytes.NewBuffer(data)
	err := gob.NewDecoder(buf).Decode(&r)
	return r, err
}

type errNotFound struct {
	error
}

func (*errNotFound) NotFoundErr() {}

type errConflict struct {
	error
}

func (*errConflict) ConflictErr() {}

type Storage struct {
	db  *bolt.DB
	Now func() time.Time
}

func New(path string, mode os.FileMode) (*Storage, error) {
	db, err := bolt.Open(path, mode, &bolt.Options{})
	if err != nil {
		return nil, err
	}
	return &Storage{db: db, Now: time.Now}, nil
}

func (s *Storage) Get(_ context.Context, keyspace, key string, into proto.Message) (version string, err error) {
	var vers string

	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyspace))
		if b == nil {
			return &errNotFound{fmt.Errorf("keyspace %s does not exist", keyspace)}
		}
		o := b.Get([]byte(key))
		if o == nil {
			return &errNotFound{fmt.Errorf("%s/%s was not found", keyspace, key)}
		}
		r, err := decodeRecord(o)
		if err != nil {
			return err
		}
		if r.Expires != nil && r.Expires.Before(s.Now()) {
			return &errNotFound{fmt.Errorf("%s/%s has expired", keyspace, key)}
		}
		vers = strconv.FormatInt(r.Version, 10)
		if err := proto.Unmarshal(r.Data, into); err != nil {
			return err
		}
		return nil
	})

	return vers, err
}

func (s *Storage) Put(ctx context.Context, keyspace, key, version string, obj proto.Message) (newVersion string, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, nil)
}

func (s *Storage) PutWithExpiry(ctx context.Context, keyspace, key, version string, obj proto.Message, expires time.Time) (newVersion string, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, &expires)
}

func (s *Storage) putWithOptionalExpiry(ctx context.Context, keyspace, key, version string, obj proto.Message, expires *time.Time) (newVersion string, err error) {
	var nvers int64
	err = s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(keyspace))
		var existing bool
		var existvers int64
		newExp := expires

		if err != nil {
			return err
		}
		// get the current record
		o := b.Get([]byte(key))
		if o != nil {
			r, err := decodeRecord(o)
			if err != nil {
				return err
			}
			// don't count expired objects
			if r.Expires == nil || r.Expires.After(s.Now()) {
				existing = true
				existvers = r.Version
				if newExp == nil {
					newExp = r.Expires
				}
			}
		}

		if existing && version == "" {
			return &errConflict{errors.New("Existing item found, but no version specified for put")}
		}
		if !existing && version != "" {
			return &errConflict{errors.New("Version specified for put, but no item specified")}
		}
		if existing {
			newvers, err := strconv.ParseInt(version, 10, 64)
			if err != nil {
				return err
			}
			if newvers != existvers {
				return &errConflict{fmt.Errorf("Update conflict: want vers %d, got %d", existvers, newvers)}
			}
		}

		// update the record
		pb, err := proto.Marshal(obj)
		if err != nil {
			return err
		}
		nvers := existvers + 1
		r := &record{
			Version: nvers,
			Data:    pb,
			Expires: newExp,
		}
		rb, err := r.encode()
		if err != nil {
			return err
		}

		return b.Put([]byte(key), rb)
	})
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(nvers, 10), nil
}

func (s *Storage) List(_ context.Context, keyspace string) ([]string, error) {
	var keys []string

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyspace))
		if b == nil {
			return &errNotFound{fmt.Errorf("keyspace %s does not exist", keyspace)}
		}
		return b.ForEach(func(k, _ []byte) error {
			keys = append(keys, string(k))
			return nil
		})
	})

	return keys, err
}

func (s *Storage) Delete(_ context.Context, keyspace, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyspace))
		if b == nil {
			return &errNotFound{fmt.Errorf("keyspace %s does not exist", keyspace)}
		}
		if b.Get([]byte(key)) == nil {
			return &errNotFound{fmt.Errorf("Key %s/%s not found", keyspace, key)}
		}
		return b.Delete([]byte(key))
	})
}
