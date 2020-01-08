package cli

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestKeychainCredentialCache(t *testing.T) {
	// This test requires access to macOS Keychain
	if os.Getenv("TEST_KEYCHAIN_CREDENTIAL_CACHE") == "" {
		t.Skip("TEST_KEYCHAIN_CREDENTIAL_CACHE not set")
		return
	}

	cache := &KeychainCredentialCache{}

	testCache(t, cache)
}

func TestEncryptedFileCredentialCache(t *testing.T) {
	dir, err := ioutil.TempDir("", "cachetest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	cache := &EncryptedFileCredentialCache{
		Dir: dir,
		PassphrasePromptFunc: func(prompt string) (passphrase string, err error) {
			return "passphrase", nil
		},
	}

	testCache(t, cache)
}

func TestMemoryWriteThroughCredentialCache(t *testing.T) {
	cache := &MemoryWriteThroughCredentialCache{
		CredentialCache: &NullCredentialCache{},
	}

	testCache(t, cache)
}

func testCache(t *testing.T, cache CredentialCache) {
	for _, tc := range []struct {
		name string
		run  func(cache CredentialCache) (*oauth2.Token, error)
		want *oauth2.Token
	}{
		{
			name: "happy path",
			run: func(cache CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"})

				if err := cache.Set("https://issuer1.test", "clientID", []string{"openid"}, []string{"acr1"}, token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer1.test", "clientID", []string{"openid"}, []string{"acr1"})
			},
			want: (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"}),
		},
		{
			name: "cache miss by issuer",
			run: func(cache CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"})

				if err := cache.Set("https://issuer2.test", "clientID", []string{"openid"}, []string{"acr1"}, token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer3.test", "clientID", []string{"openid"}, []string{"acr1"})
			},
			want: nil,
		},
		{
			name: "cache miss by client ID",
			run: func(cache CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"})

				if err := cache.Set("https://issuer4.test", "clientID1", []string{"openid"}, []string{"acr1"}, token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer4.test", "clientID2", []string{"openid"}, []string{"acr1"})
			},
			want: nil,
		},
		{
			name: "cache miss by scopes",
			run: func(cache CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"})

				if err := cache.Set("https://issuer5.test", "clientID", []string{"openid"}, []string{"acr1"}, token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer5.test", "clientID", []string{"openid", "groups"}, []string{"acr1"})
			},
			want: nil,
		},
		{
			name: "cache miss by ACR",
			run: func(cache CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]interface{}{"id_token": "zyx987"})

				if err := cache.Set("https://issuer5.test", "clientID", []string{"openid"}, []string{"acr1"}, token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer5.test", "clientID", []string{"openid"}, []string{"acr2"})
			},
			want: nil,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.run(cache)
			if err != nil {
				t.Fatal(err)
			}

			if ((tc.want == nil) != (got == nil)) || !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("want: %+v, got %+v", tc.want, got)
			}
		})
	}
}
