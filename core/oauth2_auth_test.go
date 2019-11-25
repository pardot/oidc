package core

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseAuthRequest(t *testing.T) {
	for _, tc := range []struct {
		Name        string
		Method      string
		Query       string
		WantErr     bool
		WantErrCode authErrorCode
		CmpReq      *authRequest
	}{
		{
			Name:    "Invalid method",
			Method:  "HEAD",
			WantErr: true,
		},
		{
			Name:        "Unknown response type",
			Query:       "response_type=bad",
			WantErr:     true,
			WantErrCode: authErrorCodeInvalidRequest,
		},
		{
			Name:        "Missing client ID",
			Query:       "response_type=code",
			WantErr:     true,
			WantErrCode: authErrorCodeInvalidRequest,
		},
		{
			Name: "Complete request",
			Query: fmt.Sprintf(
				"response_type=code&client_id=client&redirect_uri=%s&scope=%s&state=state",
				url.QueryEscape("https://redirect"), url.QueryEscape("openid groups"),
			),
			CmpReq: &authRequest{
				ClientID:     "client",
				RedirectURI:  "https://redirect",
				State:        "state",
				Scopes:       []string{"openid", "groups"},
				ResponseType: responseTypeCode,
				Raw: url.Values{
					"client_id":     {"client"},
					"redirect_uri":  {"https://redirect"},
					"response_type": {"code"},
					"scope":         {"openid groups"},
					"state":         {"state"},
				},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			meth := tc.Method
			if meth == "" {
				meth = "GET"
			}

			req := httptest.NewRequest(meth, "https://test/auth?"+tc.Query, nil)

			preq, err := parseAuthRequest(req)
			if err == nil && tc.WantErr {
				t.Fatal("want error, got none")
			}
			if err != nil && !tc.WantErr {
				t.Fatalf("want no err, got: %v", err)
			}
			if err != nil && tc.WantErrCode != authErrorCode("") {
				aerr, ok := err.(*authError)
				if !ok {
					t.Errorf("want error of type *authError, got %T", err)
				}
				if tc.WantErrCode != aerr.Code {
					t.Errorf("want err code %s, got: %s", tc.WantErrCode, aerr.Code)
				}
			}

			if tc.CmpReq != nil {
				if diff := cmp.Diff(tc.CmpReq, preq); diff != "" {
					t.Error(diff)
				}
			}
		})
	}
}

func TestSendCodeAuthResponse(t *testing.T) {
	for _, tc := range []struct {
		Name           string
		Resp           *codeAuthResponse
		WantRedirectTo string
	}{
		{
			Name: "valid response",
			Resp: &codeAuthResponse{
				RedirectURI: mustURL("https://redirect"),
				State:       "state",
				Code:        "code",
			},
			WantRedirectTo: "https://redirect?code=code&state=state",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://auth", nil)
			w := httptest.NewRecorder()

			sendCodeAuthResponse(w, req, tc.Resp)

			if w.Result().StatusCode < 300 || w.Result().StatusCode > 399 {
				t.Errorf("want redirect status, got %d", w.Result().StatusCode)
			}

			loc := w.Result().Header.Get("location")

			if tc.WantRedirectTo != loc {
				t.Errorf("want redirect to %s, got: %s", tc.WantRedirectTo, loc)
			}
		})
	}
}

func TestSendTokenAuthResponse(t *testing.T) {
	for _, tc := range []struct {
		Name           string
		Resp           *tokenAuthResponse
		WantRedirectTo string
	}{
		{
			Name: "valid response",
			Resp: &tokenAuthResponse{
				RedirectURI: mustURL("https://redirect"),
				State:       "state",
				Token:       "tok",
				TokenType:   tokenTypeBearer,
				Scopes:      []string{"openid"},
				ExpiresIn:   1 * time.Minute,
			},
			WantRedirectTo: "https://redirect?access_token=tok&expires_in=60&scope=openid&state=state&token_type=Bearer",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://auth", nil)
			w := httptest.NewRecorder()

			sendTokenAuthResponse(w, req, tc.Resp)

			if w.Result().StatusCode < 300 || w.Result().StatusCode > 399 {
				t.Errorf("want redirect status, got %d", w.Result().StatusCode)
			}

			loc := w.Result().Header.Get("location")

			if tc.WantRedirectTo != loc {
				t.Errorf("want redirect to %s, got: %s", tc.WantRedirectTo, loc)
			}
		})
	}
}

func mustURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic("err")
	}
	return u
}
