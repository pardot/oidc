package oidc

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	xoauth2 "golang.org/x/oauth2"
)

var errCmp = cmp.Comparer(func(x, y error) bool {
	// Two errors are equal if either Is the other.
	//
	// We need to perform the test in both directions because cmp requires
	// comparer functions to be symmetric, but errors.Is is not.
	return errors.Is(x, y) || errors.Is(y, x)
})

func TestParseExchangeError(t *testing.T) {
	for _, tc := range []struct {
		Name string
		In   error
		Want string
	}{
		{
			Name: "Generic error",
			In:   errors.New("Some rando thing happened"),
			Want: "error exchanging token: Some rando thing happened",
		},
		{
			Name: "Invalid Grant error",
			In: &xoauth2.RetrieveError{
				Response: &http.Response{
					StatusCode: 400,
					Status:     "400 Bad Request",
				},
				Body: []byte(`{"error": "invalid_grant", "error_description":"authentication failure"}`),
			},
			Want: "invalid_grant error in token request: authentication failure",
		},
		{
			Name: "Internal server error",
			In: &xoauth2.RetrieveError{
				Response: &http.Response{
					StatusCode: 500,
					Status:     "500 Internal Server Error",
				},
				Body: []byte(`Boomtown`),
			},
			Want: "http status 500 Internal Server Error: Boomtown",
		},
		{
			Name: "401 error",
			In: &xoauth2.RetrieveError{
				Response: &http.Response{
					StatusCode: 401,
					Status:     "401 Unauthorized",
					Header: http.Header{
						http.CanonicalHeaderKey("www-authenticate"): []string{"Basic"},
					},
				},
				Body: []byte(`{"error": "invalid_client", "error_description":"auth or something"}`),
			},
			Want: "invalid_client error in token request: auth or something",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			got := parseExchangeError(tc.In)

			if got.Error() != tc.Want {
				t.Errorf("want: %s, got: %s", tc.Want, got.Error())
			}
		})
	}
}
