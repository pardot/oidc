package sql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/golang/protobuf/proto"
)

type Storage struct {
	db *sql.DB
}

func New(ctx context.Context, db *sql.DB) (*Storage, error) {
	s := &Storage{
		db: db,
	}

	if err := s.migrate(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Storage) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(
		ctx,
		`create table if not exists migrations (
		idx int primary key not null,
		at timestamptz not null
		);`,
	); err != nil {
		return err
	}

	if err := s.execTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var maxIdx sql.NullInt64
		if err := tx.QueryRowContext(ctx, `select max(idx) from migrations;`).Scan(&maxIdx); err != nil {
			return err
		}

		i := 0
		if maxIdx.Valid {
			i = int(maxIdx.Int64) + 1
		}

		for ; i < len(migrations); i++ {
			if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
				return err
			}

			if _, err := tx.ExecContext(ctx, `insert into migrations (idx, at) values ($1, now());`, i); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (s *Storage) Get(ctx context.Context, keyspace, key string, into proto.Message) (version int64, err error) {
	var value []byte
	if err := s.db.QueryRowContext(
		ctx,
		`select version, value from values where keyspace=$1 and key=$2 and (expires is null or expires > now())`,
		keyspace, key,
	).Scan(&version, &value); err != nil {
		if err == sql.ErrNoRows {
			return 0, &errNotFound{err}
		}

		return 0, err
	}

	if err := proto.Unmarshal(value, into); err != nil {
		return 0, err
	}

	return version, nil
}

func (s *Storage) Put(ctx context.Context, keyspace, key string, version int64, obj proto.Message) (newVersion int64, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, nil)
}

func (s *Storage) PutWithExpiry(ctx context.Context, keyspace, key string, version int64, obj proto.Message, expires time.Time) (newVersion int64, err error) {
	return s.putWithOptionalExpiry(ctx, keyspace, key, version, obj, &expires)
}

func (s *Storage) putWithOptionalExpiry(ctx context.Context, keyspace, key string, version int64, obj proto.Message, expires *time.Time) (newVersion int64, err error) {
	value, err := proto.Marshal(obj)
	if err != nil {
		return 0, err
	}

	newVersion = version + 1

	resp, err := s.db.ExecContext(
		ctx,
		`insert into values as v
		(keyspace, key, version, value, expires)
		values ($1, $2, $3, $4, $5)
		on conflict (keyspace, key)
		do update set version=excluded.version, value=excluded.value, expires=excluded.expires
		where v.version=$6 or v.expires <= now()`,
		keyspace, key, newVersion, value, expires, version,
	)
	if err != nil {
		return 0, err
	}

	rowsAffected, err := resp.RowsAffected()
	if err != nil {
		return 0, err
	} else if rowsAffected == 0 {
		return 0, &errConflict{errors.New("conflict")}
	}

	return newVersion, nil
}

func (s *Storage) List(ctx context.Context, keyspace string) (keys []string, err error) {
	rows, err := s.db.QueryContext(
		ctx,
		`select key from values
		where keyspace=$1 and (expires is null or expires > now())`,
		keyspace,
	)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}

		keys = append(keys, key)
	}

	return keys, nil
}

func (s *Storage) Delete(ctx context.Context, keyspace, key string) error {
	res, err := s.db.ExecContext(
		ctx,
		`delete from values where keyspace=$1 and key=$2`,
		keyspace, key,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errNotFound{errors.New("not found")}
	}

	return nil
}

func (s *Storage) execTx(ctx context.Context, f func(ctx context.Context, tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if err := f(ctx, tx); err != nil {
		// Not much we can do about an error here, but at least the database will
		// eventually cancel it on its own if it fails
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

var migrations = []string{
	`create table values(
		keyspace text not null,
		key text not null,
		version bigint not null,
		value bytea not null,
		expires timestamptz,
		primary key(keyspace, key)
	);

	create index values_expires on values (expires);
	`,
}
