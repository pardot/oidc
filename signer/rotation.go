package signer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/sirupsen/logrus"
)

var errAlreadyRotated = errors.New("keys already rotated by another server instance")

// ErrNotFound is the error returned by storages if a resource cannot be found.
var ErrNotFound = errors.New("not found")

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

type Storage interface {
	GetKeys() (Keys, error)
	UpdateKeys(updater func(old Keys) (Keys, error)) error
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
	storage Storage

	strategy RotationStrategy
	now      func() time.Time

	logger logrus.FieldLogger
}

func NewRotating(l logrus.FieldLogger, storage Storage, strategy RotationStrategy) *RotatingSigner {
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
func (r *RotatingSigner) Start(ctx context.Context) {
	// Try to rotate immediately so properly configured storages will have keys.
	if err := r.rotate(); err != nil {
		if err == errAlreadyRotated {
			r.logger.Infof("Key rotation not needed: %v", err)
		} else {
			r.logger.Errorf("failed to rotate keys: %v", err)
		}
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 30):
				if err := r.rotate(); err != nil {
					r.logger.Errorf("failed to rotate keys: %v", err)
				}
			}
		}
	}()
}

func (r *RotatingSigner) rotate() error {
	keys, err := r.storage.GetKeys()
	if err != nil && err != ErrNotFound {
		return fmt.Errorf("get keys: %v", err)
	}
	if r.now().Before(keys.NextRotation) {
		return nil
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

	var nextRotation time.Time
	err = r.storage.UpdateKeys(func(keys Keys) (Keys, error) {
		tNow := r.now()

		// if you are running multiple instances of dex, another instance
		// could have already rotated the keys.
		if tNow.Before(keys.NextRotation) {
			return Keys{}, errAlreadyRotated
		}

		expired := func(key VerificationKey) bool {
			return tNow.After(key.Expiry)
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
			verificationKey := VerificationKey{
				PublicKey: keys.SigningKeyPub,
				// After demoting the signing key, keep the token around for at least
				// the amount of time an ID Token is valid for. This ensures the
				// verification key won't expire until all ID Tokens it's signed
				// expired as well.
				Expiry: tNow.Add(r.strategy.idTokenValidFor),
			}
			keys.VerificationKeys = append(keys.VerificationKeys, verificationKey)
		}

		nextRotation = r.now().Add(r.strategy.rotationFrequency)
		keys.SigningKey = priv
		keys.SigningKeyPub = pub
		keys.NextRotation = nextRotation
		return keys, nil
	})
	if err != nil {
		return err
	}

	r.logger.Infof("keys rotated, next rotation: %s", nextRotation)
	return nil
}

// PublicKeys returns a keyset of all valid signer public keys considered
// valid for signed tokens
func (r *RotatingSigner) PublicKeys(_ context.Context) (*jose.JSONWebKeySet, error) {
	keys, err := r.storage.GetKeys()
	if err != nil {
		return nil, err
	}
	vks := []jose.JSONWebKey{}
	if keys.SigningKeyPub != nil {
		vks = append(vks, *keys.SigningKeyPub)
	}
	for _, k := range keys.VerificationKeys {
		vks = append(vks, *k.PublicKey)
	}
	return &jose.JSONWebKeySet{
		Keys: vks,
	}, nil
}

// SignerAlg returns the algorithm the signer uses
func (r *RotatingSigner) SignerAlg(_ context.Context) (jose.SignatureAlgorithm, error) {
	keys, err := r.storage.GetKeys()
	if err != nil {
		return jose.SignatureAlgorithm(""), err
	}
	return jose.SignatureAlgorithm(keys.SigningKey.Algorithm), nil
}

// Sign the provided data
func (r *RotatingSigner) Sign(ctx context.Context, data []byte) (signed []byte, err error) {
	keys, err := r.storage.GetKeys()
	if err != nil {
		return nil, err
	}
	sk := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(keys.SigningKey.Algorithm),
		Key:       keys.SigningKey.Key,
	}
	return sign(ctx, sk, data)
}

// VerifySignature verifies the signature given token against the current signers
func (r *RotatingSigner) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	keys, err := r.storage.GetKeys()
	if err != nil {
		return nil, err
	}
	vks := []jose.JSONWebKey{}
	if keys.SigningKeyPub != nil {
		vks = append(vks, *keys.SigningKeyPub)
	}
	for _, k := range keys.VerificationKeys {
		vks = append(vks, *k.PublicKey)
	}

	return verifySignature(ctx, vks, jwt)
}
