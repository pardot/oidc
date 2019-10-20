package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/text/language"
	"golang.org/x/text/search"
)

func TestWriteError(t *testing.T) {
	for _, tc := range []struct {
		Name string
		Err  error
		Cmp  func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		{
			Name: "Generic error",
			Err:  errors.New("errortext"),
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusInternalServerError {
					t.Error("error status should be 500")
				}
				if containsInsensitive(rec.Body.String(), "errortext") {
					t.Error("generic error response body should never expose error details to user")
				}
			},
		},
		{
			Name: "HTTP error should never expose internal details",
			Err:  &httpError{Cause: errors.New("cause"), CauseMsg: "causemsg"},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if containsInsensitive(rec.Body.String(), "cause") {
					t.Error("generic error response body should never expose error details to user")
				}
				if containsInsensitive(rec.Body.String(), "causemsg") {
					t.Error("generic error response body should never expose error details to user")
				}
			},
		},
		{
			Name: "HTTP error should pass through status",
			Err:  &httpError{Code: http.StatusNotImplemented},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusNotImplemented {
					t.Error("error status should be 501")
				}
			},
		},
		{
			Name: "HTTP error should pass message to user",
			Err:  &httpError{Message: "usermessage"},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if !containsInsensitive(rec.Body.String(), "usermessage") {
					t.Error("http error should pass message to user")
				}
			},
		},
		{
			Name: "Auth error should redirect to the given callback passing details",
			Err:  &authError{State: "state", Code: authErrorCodeAccessDenied, Description: "access denied", RedirectURI: "https://callback"},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != 302 {
					t.Errorf("want 302 redir, got %d", rec.Code)
				}

				loc := rec.Header().Get("location")

				if !strings.HasPrefix(loc, "https://callback") {
					t.Errorf("want redirect to callback, got: %s", loc)
				}

				locp, err := url.Parse(loc)
				if err != nil {
					t.Fatalf("failed to parse callback URL: %v", err)
				}

				q := locp.Query()

				if q.Get("state") != "state" {
					t.Errorf("want state, got: %s", q.Get("state"))
				}
				if q.Get("error") != string(authErrorCodeAccessDenied) {
					t.Errorf("want error %s, got: %s", string(authErrorCodeAccessDenied), q.Get("error"))
				}
				if q.Get("error_description") != "access denied" {
					t.Errorf("want error \"access denied\", got: %s", q.Get("error_description"))
				}
			},
		},
		{
			Name: "Token error should return JSON details",
			Err:  &tokenError{Code: tokenErrorCodeInvalidGrant, Description: "grant is bad", ErrorURI: "https://error/info"},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusBadRequest {
					t.Errorf("want 400, got %d", rec.Code)
				}

				te := &tokenError{}

				if err := json.NewDecoder(rec.Body).Decode(te); err != nil {
					t.Fatalf("failed to unmarshal response JSON: %v", err)
				}

				if te.Code != tokenErrorCodeInvalidGrant {
					t.Errorf("want code %s, got %s", tokenErrorCodeInvalidClient, te.Code)
				}

				if te.Description != "grant is bad" {
					t.Errorf("want description \"grant is bad\", got: %s", te.Description)
				}
			},
		},
		{
			Name: "Token error can set www-authenticate header",
			Err:  &tokenError{Code: tokenErrorCodeInvalidClient, WWWAuthenticate: "Basic"},
			Cmp: func(t *testing.T, rec *httptest.ResponseRecorder) {
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("want 401, got %d", rec.Code)
				}

				if wwa := rec.Header().Get("www-authenticate"); wwa != "Basic" {
					t.Errorf("want www-authenticate Basic, got: %s", wwa)
				}
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()

			err := writeError(rec, req, tc.Err)
			if err != nil {
				t.Fatalf("unexpected error calling writeError: %v", err)
			}

			tc.Cmp(t, rec)
		})
	}
}

func containsInsensitive(str, substring string) bool {
	s := search.New(language.Und, search.IgnoreCase)
	i, _ := s.IndexString(str, substring)
	return i >= 0
}
