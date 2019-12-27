package idtoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestIDTokenMarshaling(t *testing.T) {
	for _, tc := range []struct {
		Name     string
		Token    Claims
		WantJSON string
	}{
		{
			Name: "basic",
			Token: Claims{
				Issuer:   "http://issuer",
				Audience: Audience{"aud"},
				Expiry:   NewUnixTime(mustTime(time.Parse("2006-Jan-02", "2019-Nov-20"))),
				Extra: map[string]interface{}{
					"hello": "world",
				},
			},
			WantJSON: `{
  "aud": "aud",
  "exp": 1574208000,
  "hello": "world",
  "iss": "http://issuer"
}`,
		},
		{
			Name: "multiple audiences",
			Token: Claims{
				Audience: Audience{"aud1", "aud2"},
			},
			WantJSON: `{
  "aud": [
    "aud1",
    "aud2"
  ]
}`,
		},
		{
			Name: "extra shouldn't shadow primary fields",
			Token: Claims{
				Issuer: "http://issuer",
				Extra: map[string]interface{}{
					"iss": "http://bad",
				},
			},
			WantJSON: `{
  "iss": "http://issuer"
}`,
		},
		{
			Name: "complex extra",
			Token: Claims{
				Issuer:   "http://127.0.0.1:62281",
				Subject:  "CgVmb29pZBIEbW9jaw",
				Audience: Audience{"testclient"},
				Expiry:   1576187854,
				IssuedAt: 1576187824,
				AuthTime: 1576187824,
				Extra: map[string]interface{}{
					"email":    "foo@bar.com",
					"groups":   []string{"foo", "bar"},
					"username": "foo",
				},
			},
			WantJSON: `{
  "aud": "testclient",
  "auth_time": 1576187824,
  "email": "foo@bar.com",
  "exp": 1576187854,
  "groups": [
    "foo",
    "bar"
  ],
  "iat": 1576187824,
  "iss": "http://127.0.0.1:62281",
  "sub": "CgVmb29pZBIEbW9jaw",
  "username": "foo"
}`,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jb, err := json.MarshalIndent(tc.Token, "", "  ")
			if err != nil {
				t.Fatalf("Unexpected error marshaling JSON: %v", err)
			}

			if diff := cmp.Diff(tc.WantJSON, string(jb)); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestIDTokenUnmarshaling(t *testing.T) {
	for _, tc := range []struct {
		Name      string
		JSON      string
		WantToken Claims
	}{
		{
			Name: "basic",
			JSON: `{
  "aud": "aud",
  "exp": 1574208000,
  "hello": "world",
  "iss": "http://issuer"
}`,
			WantToken: Claims{
				Issuer:   "http://issuer",
				Audience: Audience{"aud"},
				Expiry:   NewUnixTime(mustTime(time.Parse("2006-Jan-02", "2019-Nov-20"))),
				Extra: map[string]interface{}{
					"hello": "world",
				},
			},
		},
		{
			Name: "Multiple audiences",
			JSON: `{
  "aud": ["aud1", "aud2"]
}`,
			WantToken: Claims{
				Audience: Audience{"aud1", "aud2"},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tok := Claims{}
			if err := json.Unmarshal([]byte(tc.JSON), &tok); err != nil {
				t.Fatalf("Unexpected error unmarshaling JSON: %v", err)
			}

			if diff := cmp.Diff(tc.WantToken, tok, cmpopts.IgnoreUnexported(Claims{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func mustTime(t time.Time, err error) time.Time {
	if err != nil {
		panic(err)
	}
	return t
}
