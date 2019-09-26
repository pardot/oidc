package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/golang/protobuf/ptypes"
	storagepb "github.com/pardot/deci/proto/deci/storage/v1beta1"
	"github.com/pardot/deci/storage"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

const (
	keysPrefix = "signer-keys"
	// we only have one set, so just use a fixed key
	keysKey = "key"
)

// VerificationKey is a rotated signing key which can still be used to verify
// signatures.
type VerificationKey struct {
	PublicKey *jose.JSONWebKey `json:"publicKey"`
	Expiry    time.Time        `json:"expiry"`
}

// Keys hold encryption and signing keys.
type Keys struct {
	// Key for creating and verifying signatures. These may be nil.
	SigningKey    *jose.JSONWebKey
	SigningKeyPub *jose.JSONWebKey

	// Old signing keys which have been rotated but can still be used to validate
	// existing signatures.
	VerificationKeys []VerificationKey

	// The next time the signing key will rotate.
	//
	// For caching purposes, implementations MUST NOT update keys before this time.
	NextRotation time.Time
}

// RotationStrategy describes a strategy for generating cryptographic keys, how
// often to rotate them, and how long they can validate signatures after rotation.
type RotationStrategy struct {
	// Time between rotations.
	rotationFrequency time.Duration

	// After being rotated how long should the key be kept around for validating
	// signatues?
	idTokenValidFor time.Duration

	// Keys are always RSA keys. Though cryptopasta recommends ECDSA keys, not every
	// client may support these (e.g. github.com/coreos/go-oidc/oidc).
	key func() (*rsa.PrivateKey, error)
}

// StaticRotationStrategy returns a strategy which never rotates keys.
func StaticRotationStrategy(key *rsa.PrivateKey) RotationStrategy {
	return RotationStrategy{
		// Setting these values to 100 years is easier than having a flag indicating no rotation.
		rotationFrequency: time.Hour * 8760 * 100,
		idTokenValidFor:   time.Hour * 8760 * 100,
		key:               func() (*rsa.PrivateKey, error) { return key, nil },
	}
}

// DefaultRotationStrategy returns a strategy which rotates keys every provided period,
// holding onto the public parts for some specified amount of time.
func DefaultRotationStrategy(rotationFrequency, idTokenValidFor time.Duration) RotationStrategy {
	return RotationStrategy{
		rotationFrequency: rotationFrequency,
		idTokenValidFor:   idTokenValidFor,
		key: func() (*rsa.PrivateKey, error) {
			return rsa.GenerateKey(rand.Reader, 2048)
		},
	}
}

// RotatingSigner is a OIDC signer that automatically rotates signing keys
type RotatingSigner struct {
	storage storage.Storage

	strategy RotationStrategy
	now      func() time.Time

	logger logrus.FieldLogger
}

func NewRotating(l logrus.FieldLogger, storage storage.Storage, strategy RotationStrategy) *RotatingSigner {
	return &RotatingSigner{
		storage:  storage,
		logger:   l,
		strategy: strategy,
		now:      time.Now,
	}
}

// Start begins key rotation in a new goroutine, closing once the context is canceled.
//
// The method blocks until after the first attempt to rotate keys has completed. That way
// healthy storages will return from this call with valid keys.
func (r *RotatingSigner) Start(ctx context.Context) error {
	// Try to rotate immediately so properly configured storages will have keys.
	if err := r.rotate(); err != nil {
		return err
	}

	r.logger.Info("starting key rotation loop")
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 30):
				if err := r.rotate(); err != nil {
					r.logger.WithError(err).Error("failed to rotate keys")
				}
			}
		}
	}()

	return nil
}

func (r *RotatingSigner) rotate() error {
	keys := &storagepb.Keys{}
	kver, err := r.storage.Get(context.TODO(), keysPrefix, keysKey, keys)
	if err != nil && !storage.IsNotFoundErr(err) {
		return fmt.Errorf("get keys: %v", err)
	}
	if keys.NextRotation != nil {
		nr, err := ptypes.Timestamp(keys.NextRotation)
		if err != nil {
			return err
		}
		if r.now().Before(nr) {
			return nil
		}
	}
	r.logger.Infof("keys expired, rotating")

	// Generate the key outside of a storage transaction.
	key, err := r.strategy.key()
	if err != nil {
		return fmt.Errorf("generate key: %v", err)
	}
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	keyID := hex.EncodeToString(b)
	priv := &jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	pub := &jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}

	tNow := r.now()

	expired := func(key *storagepb.VerificationKey) bool {
		kexp, err := ptypes.Timestamp(key.Expiry)
		if err != nil {
			panic(err)
		}
		return tNow.After(kexp)
	}

	// Remove any verification keys that have expired.
	i := 0
	for _, key := range keys.VerificationKeys {
		if !expired(key) {
			keys.VerificationKeys[i] = key
			i++
		}
	}
	keys.VerificationKeys = keys.VerificationKeys[:i]

	if keys.SigningKeyPub != nil {
		// Move current signing key to a verification only key, throwing
		// away the private part.
		vkexp, err := ptypes.TimestampProto(tNow.Add(r.strategy.idTokenValidFor))
		if err != nil {
			return err
		}
		verificationKey := &storagepb.VerificationKey{
			PublicKey: keys.SigningKeyPub,
			// After demoting the signing key, keep the token around for at least
			// the amount of time an ID Token is valid for. This ensures the
			// verification key won't expire until all ID Tokens it's signed
			// expired as well.
			Expiry: vkexp,
		}
		keys.VerificationKeys = append(keys.VerificationKeys, verificationKey)
	}

	nextRotation, err := ptypes.TimestampProto(r.now().Add(r.strategy.rotationFrequency))
	if err != nil {
		return err
	}
	privb, err := json.Marshal(priv)
	if err != nil {
		return err
	}
	keys.SigningKey = privb
	pubb, err := json.Marshal(pub)
	if err != nil {
		return err
	}
	keys.SigningKeyPub = pubb
	keys.NextRotation = nextRotation

	if _, err := r.storage.Put(context.TODO(), keysPrefix, keysKey, kver, keys); err != nil {
		if storage.IsConflictErr(err) {
			// Assume someone else updated, so roll with it
			return nil
		}
		return err
	}

	r.logger.Infof("keys rotated, next rotation: %s", nextRotation)
	return nil
}

// PublicKeys returns a keyset of all valid signer public keys considered
// valid for signed tokens
func (r *RotatingSigner) PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, err := r.pubKeys(ctx)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKeySet{
		Keys: keys,
	}, nil
}

// SignerAlg returns the algorithm the signer uses
func (r *RotatingSigner) SignerAlg(ctx context.Context) (jose.SignatureAlgorithm, error) {
	keys := &storagepb.Keys{}
	_, err := r.storage.Get(ctx, keysPrefix, keysKey, keys)
	if err != nil {
		return jose.SignatureAlgorithm(""), err
	}
	swk := jose.JSONWebKey{}
	if err := json.Unmarshal(keys.SigningKey, &swk); err != nil {
		return jose.SignatureAlgorithm(""), err
	}
	return jose.SignatureAlgorithm(swk.Algorithm), nil
}

// Sign the provided data
func (r *RotatingSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	keys := &storagepb.Keys{}
	_, err := r.storage.Get(ctx, keysPrefix, keysKey, keys)
	if err != nil {
		return nil, err
	}
	swk := jose.JSONWebKey{}
	if err := json.Unmarshal(keys.SigningKey, &swk); err != nil {
		return nil, err
	}
	sk := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(swk.Algorithm),
		Key:       swk,
	}
	return sign(ctx, sk, data)
}

// VerifySignature verifies the signature given token against the current signers
func (r *RotatingSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	keys, err := r.pubKeys(ctx)
	if err != nil {
		return nil, err
	}
	return verifySignature(ctx, keys, jwt)
}

// pubKeys returns all currently valid public keys for this instance.
func (r *RotatingSigner) pubKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	keys := &storagepb.Keys{}
	_, err := r.storage.Get(ctx, keysPrefix, keysKey, keys)
	if err != nil {
		return nil, err
	}
	vks := []jose.JSONWebKey{}
	if keys.SigningKeyPub != nil {
		sk := jose.JSONWebKey{}
		if err := json.Unmarshal(keys.SigningKeyPub, &sk); err != nil {
			return nil, err
		}
		vks = append(vks, sk)
	}
	for _, k := range keys.VerificationKeys {
		vk := jose.JSONWebKey{}
		if err := json.Unmarshal(k.PublicKey, &vk); err != nil {
			return nil, err
		}
		vks = append(vks, vk)
	}
	return vks, nil
}
