package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseToken(t *testing.T) {
	for _, tc := range []struct {
		Name        string
		Req         func() *http.Request
		WantErr     bool
		WantErrCode tokenErrorCode
		Want        *tokenRequest
	}{
		{
			Name: "Bad method",
			Req: func() *http.Request {
				return httptest.NewRequest("HEAD", "/", nil)
			},
			WantErr: true,
		},
		{
			Name: "Good query",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
				"grant_type":    "authorization_code",
			}),
			Want: &tokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "client",
				ClientSecret: "secret",
			},
		},
		{
			Name: "Basic auth creds",
			Req: func() *http.Request {
				req := queryReq(map[string]string{
					"code":         "acode",
					"redirect_uri": "https://redirect",
					"grant_type":   "authorization_code",
				})()
				req.SetBasicAuth("clientuser", "clientsecret")
				return req
			},
			Want: &tokenRequest{
				GrantType:    GrantTypeAuthorizationCode,
				Code:         "acode",
				RedirectURI:  "https://redirect",
				ClientID:     "clientuser",
				ClientSecret: "clientsecret",
			},
		},
		{
			Name: "Invalid grant type",
			Req: queryReq(map[string]string{
				"code":          "acode",
				"redirect_uri":  "https://redirect",
				"client_id":     "client",
				"client_secret": "secret",
			}),
			WantErr:     true,
			WantErrCode: tokenErrorCodeInvalidGrant,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			resp, err := parseTokenRequest(tc.Req())
			if tc.WantErr && err == nil {
				t.Fatal("want err, got none")
			}
			if !tc.WantErr && err != nil {
				t.Fatalf("want no error, got: %v", err)
			}
			if tc.WantErrCode != tokenErrorCode("") {
				terr, ok := err.(*tokenError)
				if !ok {
					t.Fatalf("want tokenError, got: %v of type %T", err, err)
				}
				if tc.WantErrCode != terr.Code {
					t.Fatalf("want err code %s, got: %s", tc.WantErrCode, terr.Code)
				}
			}

			if diff := cmp.Diff(tc.Want, resp); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func queryReq(query map[string]string) func() *http.Request {
	f := url.Values{}
	for k, v := range query {
		f[k] = []string{v}
	}

	return func() *http.Request {
		req := httptest.NewRequest("POST", "https://token", strings.NewReader(f.Encode()))
		req.Header.Add("content-type", "application/x-www-form-urlencoded")
		return req
	}
}

func TestWriteTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Resp *tokenResponse
		Want map[string]interface{}
	}{
		{
			Name: "valid response",
			Resp: &tokenResponse{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresIn:    1 * time.Minute,
				RefreshToken: "refresh",
				Scopes:       []string{"openid"},
				ExtraParams: map[string]interface{}{
					"id_token": "beer",
				},
			},
			Want: map[string]interface{}{
				"access_token":  "access",
				"expires_in":    float64(60),
				"id_token":      "beer",
				"refresh_token": "refresh",
				"scope":         "openid",
				"token_type":    "Bearer",
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()

			_ = writeTokenResponse(w, tc.Resp)

			if w.Result().StatusCode != 200 {
				t.Errorf("want OK status, got %d", w.Result().StatusCode)
			}

			got := map[string]interface{}{}
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.Want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
