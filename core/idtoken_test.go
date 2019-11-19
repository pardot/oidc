package core

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
		Token    IDToken
		WantJSON string
	}{
		{
			Name: "basic",
			Token: IDToken{
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
			Token: IDToken{
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
			Token: IDToken{
				Issuer: "http://issuer",
				Extra: map[string]interface{}{
					"iss": "http://bad",
				},
			},
			WantJSON: `{
  "iss": "http://issuer"
}`,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			jb, err := json.MarshalIndent(&tc.Token, "", "  ")
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
		WantToken IDToken
	}{
		{
			Name: "basic",
			JSON: `{
  "aud": "aud",
  "exp": 1574208000,
  "hello": "world",
  "iss": "http://issuer"
}`,
			WantToken: IDToken{
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
			WantToken: IDToken{
				Audience: Audience{"aud1", "aud2"},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tok := IDToken{}
			if err := json.Unmarshal([]byte(tc.JSON), &tok); err != nil {
				t.Fatalf("Unexpected error unmarshaling JSON: %v", err)
			}

			if diff := cmp.Diff(tc.WantToken, tok, cmpopts.IgnoreUnexported(IDToken{})); diff != "" {
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
