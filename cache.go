package oidc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/oauth2"
)

type PassphrasePromptFunc func(prompt string) (passphrase string, err error)

type oauth2TokenWithExtra oauth2.Token

func (t *oauth2TokenWithExtra) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"access_token":  t.AccessToken,
		"token_type":    t.TokenType,
		"refresh_token": t.RefreshToken,
		"expiry":        t.Expiry,
		"id_token":      (*oauth2.Token)(t).Extra("id_token"),
	}

	return json.Marshal(m)
}

func (t *oauth2TokenWithExtra) UnmarshalJSON(b []byte) error {
	s := struct {
		AccessToken  string    `json:"access_token"`
		TokenType    string    `json:"token_type"`
		RefreshToken string    `json:"refresh_token"`
		Expiry       time.Time `json:"expiry"`
		IDToken      string    `json:"id_token"`
	}{}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	t2 := new(oauth2.Token)
	t2.AccessToken = s.AccessToken
	t2.TokenType = s.TokenType
	t2.RefreshToken = s.RefreshToken
	t2.Expiry = s.Expiry
	t2 = t2.WithExtra(map[string]interface{}{"id_token": s.IDToken})

	*t = oauth2TokenWithExtra(*t2)
	return nil
}

// CredentialCache is capable of caching and retrieving OpenID Connect tokens.
// At this time, CredentialCache implementations are not required to be
// goroutine safe. Code that uses a CredentialCache should synchronize access
// to the caches if goroutine safety is needed.
type CredentialCache interface {
	// Get returns a token from cache for the given issuer, clientID, scopes
	// and ACR values. Cache misses are _not_ considered an error, so a
	// cache miss will be returned as `(nil, nil)`
	Get(issuer string, clientID string, scopes []string, acrValues []string) (*oauth2.Token, error)
	// Set sets a token in the cache for the given issuer, clientID, scopes
	// and ACR values.
	Set(issuer string, clientID string, scopes []string, acrValues []string, token *oauth2.Token) error
	// Available returns true if the credential cache is supported on this
	// platform or environment.
	Available() bool
}

// BestCredentialCache returns the most preferred available credential client
// for the platform and environment.
func BestCredentialCache() CredentialCache {
	for _, c := range []CredentialCache{
		&KeychainCredentialCache{},
		&EncryptedFileCredentialCache{},
	} {
		if c.Available() {
			return c
		}
	}

	return &NullCredentialCache{}
}

type KeychainCredentialCache struct{}

var _ CredentialCache = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) Get(issuer string, clientID string, scopes []string, acrValues []string) (*oauth2.Token, error) {
	cmd := exec.Command(
		"/usr/bin/security",
		"find-generic-password",
		"-s", issuer,
		"-a", k.account(clientID, scopes, acrValues),
		"-w",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("could not be found")) {
			return nil, nil
		}

		return nil, errors.Wrapf(err, "%s", string(out))
	}

	var token oauth2TokenWithExtra
	if err := json.Unmarshal(out, &token); err != nil {
		return nil, errors.Wrap(err, "failed to decode token")
	}

	return (*oauth2.Token)(&token), nil
}

func (k *KeychainCredentialCache) Set(issuer string, clientID string, scopes []string, acrValues []string, token *oauth2.Token) error {
	b, err := json.Marshal((*oauth2TokenWithExtra)(token))
	if err != nil {
		return errors.Wrap(err, "failed to encode token")
	}

	cmd := exec.Command(
		"/usr/bin/security",
		"add-generic-password",
		"-s", issuer,
		"-a", k.account(clientID, scopes, acrValues),
		"-w", string(b),
		"-U",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "%s", string(out))
	}

	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}

	_, err := os.Stat("/usr/bin/security")

	return err == nil
}

func (k *KeychainCredentialCache) account(clientID string, scopes []string, acrValues []string) string {
	acrValues = copyAndSortStringSlice(acrValues)
	scopes = copyAndSortStringSlice(scopes)

	return fmt.Sprintf(
		"%s;%s;%s",
		clientID,
		strings.Join(scopes, ","),
		strings.Join(acrValues, ","),
	)
}

const encryptedFileKeySize = 32
const encryptedFileNonceSize = 24
const encryptedFileSaltSize = 8

type EncryptedFileCredentialCache struct {
	// Dir is the path where encrypted cache files will be stored.
	// If empty, defaults to ~/.oidc-cache/
	Dir string

	// PassphrasePromptFunc is a function that prompts the user to enter a
	// passphrase used to encrypt and decrypt a file.
	PassphrasePromptFunc
}

var _ CredentialCache = &EncryptedFileCredentialCache{}

func (e *EncryptedFileCredentialCache) Get(issuer string, clientID string, scopes []string, acrValues []string) (*oauth2.Token, error) {
	dir, err := e.resolveDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.Wrap(err, "failed to create directory")
	}

	filename := path.Join(dir, e.cacheFilename(issuer, clientID, scopes, acrValues))
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, errors.Wrapf(err, "failed to read file %q", filename)
	}

	if len(contents) < encryptedFileNonceSize {
		return nil, fmt.Errorf("file %q missing nonce", filename)
	}

	// File structure is:
	// 24 bytes: nonce
	// 8 bytes: salt
	// N bytes: ciphertext
	var nonce [encryptedFileNonceSize]byte
	copy(nonce[:], contents)
	var salt [encryptedFileSaltSize]byte
	copy(salt[:], contents[encryptedFileNonceSize:])
	ciphertext := contents[encryptedFileNonceSize+encryptedFileSaltSize:]

	passphrase, err := (e.promptFuncOrDefault())(fmt.Sprintf("Enter passphrase for decrypting %s token", issuer))
	if err != nil {
		return nil, err
	}

	key, err := e.passphraseToKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, nil
	}

	token := new(oauth2TokenWithExtra)
	if err := json.Unmarshal(plaintext, token); err != nil {
		return nil, errors.Wrap(err, "failed to decode token")
	}

	return (*oauth2.Token)(token), nil
}

func (e *EncryptedFileCredentialCache) Set(issuer string, clientID string, scopes []string, acrValues []string, token *oauth2.Token) error {
	dir, err := e.resolveDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.Wrap(err, "failed to create directory")
	}

	var nonce [encryptedFileNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return errors.Wrap(err, "failed to generate nonce")
	}

	var salt [encryptedFileSaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return errors.Wrap(err, "failed to generate salt")
	}

	passphrase, err := e.promptFuncOrDefault()(fmt.Sprintf("Enter passphrase for encrypting %s token", issuer))
	if err != nil {
		return err
	}

	key, err := e.passphraseToKey(passphrase, salt)
	if err != nil {
		return err
	}

	plaintext, err := json.Marshal((*oauth2TokenWithExtra)(token))
	if err != nil {
		return errors.Wrap(err, "failed to encode token")
	}

	ciphertext := secretbox.Seal(nil, plaintext, &nonce, &key)

	// Writes to a bytes.Buffer always succeed (or panic)
	buf := new(bytes.Buffer)
	_, _ = buf.Write(nonce[:])
	_, _ = buf.Write(salt[:])
	_, _ = buf.Write(ciphertext)

	filename := path.Join(dir, e.cacheFilename(issuer, clientID, scopes, acrValues))
	if err := ioutil.WriteFile(filename, buf.Bytes(), 0600); err != nil {
		return errors.Wrapf(err, "failed to write file %q", filename)
	}

	return nil
}

func (e *EncryptedFileCredentialCache) Available() bool {
	return true
}

func (e *EncryptedFileCredentialCache) resolveDir() (string, error) {
	dir := e.Dir
	if dir == "" {
		dir = "~/.oidc-cache"
	}

	if strings.HasPrefix(dir, "~/") {
		home, err := homedir.Dir()
		if err != nil {
			return "", errors.Wrap(err, "unable to determine home directory")
		}

		dir = path.Join(home, dir[2:])
	}

	return dir, nil
}

func (e *EncryptedFileCredentialCache) cacheFilename(issuer string, clientID string, scopes []string, acrValues []string) string {
	acrValues = copyAndSortStringSlice(acrValues)
	scopes = copyAndSortStringSlice(scopes)

	// A hash is used to avoid special characters in filenames
	hsh := sha256.Sum256([]byte(
		fmt.Sprintf(
			"%s;%s;%s;%s",
			issuer,
			clientID,
			strings.Join(scopes, ","),
			strings.Join(acrValues, ","),
		),
	))

	return hex.EncodeToString(hsh[:]) + ".enc"
}

func (e *EncryptedFileCredentialCache) passphraseToKey(passphrase string, salt [encryptedFileSaltSize]byte) ([encryptedFileKeySize]byte, error) {
	var akey [encryptedFileKeySize]byte

	key, err := scrypt.Key([]byte(passphrase), salt[:], 1<<15, 8, 1, encryptedFileKeySize)
	if err != nil {
		return akey, err
	}

	copy(akey[:], key)
	return akey, nil
}

func (e *EncryptedFileCredentialCache) promptFuncOrDefault() PassphrasePromptFunc {
	if e.PassphrasePromptFunc != nil {
		return e.PassphrasePromptFunc
	}

	return func(prompt string) (string, error) {
		if cp := os.Getenv("OIDC_CACHE_PASSPHRASE_DO_NOT_USE"); cp != "" {
			return cp, nil
		}

		fmt.Printf("%s: ", prompt)
		passphrase, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Println()

		return string(passphrase), nil
	}
}

// MemoryWriteThroughCredentialCache is a write-through cache for another
// underlying CredentialCache. If a credential has been previously requested
// from the underlying store, it is read from memory the next time it is
// requested.
//
// MemoryWriteThroughCredentialCache is useful when the underlying store
// requires user input (e.g., a passphrase) or is otherwise expensive.
type MemoryWriteThroughCredentialCache struct {
	CredentialCache

	m map[string]*oauth2.Token
}

var _ CredentialCache = &MemoryWriteThroughCredentialCache{}

func (c *MemoryWriteThroughCredentialCache) Get(issuer string, clientID string, scopes []string, acrValues []string) (*oauth2.Token, error) {
	cacheKey := c.cacheKey(issuer, clientID, scopes, acrValues)

	if token := c.m[cacheKey]; token != nil {
		return token, nil
	}

	token, err := c.CredentialCache.Get(issuer, clientID, scopes, acrValues)
	if err != nil {
		return nil, err
	}

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return token, nil
}

func (c *MemoryWriteThroughCredentialCache) Set(issuer string, clientID string, scopes []string, acrValues []string, token *oauth2.Token) error {
	err := c.CredentialCache.Set(issuer, clientID, scopes, acrValues, token)
	if err != nil {
		return err
	}

	cacheKey := c.cacheKey(issuer, clientID, scopes, acrValues)

	if c.m == nil {
		c.m = make(map[string]*oauth2.Token)
	}
	c.m[cacheKey] = token

	return nil
}

func (c *MemoryWriteThroughCredentialCache) Available() bool {
	return true
}

func (c *MemoryWriteThroughCredentialCache) cacheKey(issuer string, clientID string, scopes []string, acrValues []string) string {
	acrValues = copyAndSortStringSlice(acrValues)
	scopes = copyAndSortStringSlice(scopes)

	return fmt.Sprintf(
		"%s;%s;%s;%s",
		issuer,
		clientID,
		strings.Join(scopes, ","),
		strings.Join(acrValues, ","),
	)
}

// NullCredentialCache will not cache tokens. Used it to opt out of caching.
type NullCredentialCache struct{}

var _ CredentialCache = &NullCredentialCache{}

func (c *NullCredentialCache) Get(issuer string, clientID string, scopes []string, acrValues []string) (*oauth2.Token, error) {
	return nil, nil
}

func (c *NullCredentialCache) Set(issuer string, clientID string, scopes []string, acrValues []string, token *oauth2.Token) error {
	return nil
}

func (c *NullCredentialCache) Available() bool {
	return true
}

// copyAndSortStringSlice returns a sorted list of strings without modifying
// the original slice
func copyAndSortStringSlice(s []string) []string {
	sc := make([]string, 0, len(s))
	sc = append(sc, s...)

	sort.Strings(sc)
	return sc
}
