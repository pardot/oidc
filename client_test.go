package oidc

import (
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestAuthURLOpts(t *testing.T) {
	c := &Client{
		o2cfg: oauth2.Config{
			ClientID: "cid",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://auth",
			},
			Scopes:      []string{"openid"},
			RedirectURL: "https://redir",
		},
	}

	// make sure scopes don't cross invocations
	_ = c.AuthCodeURL("state", AddScopes([]string{"scope1", "scope2"}))
	u2 := c.AuthCodeURL("state", AddScopes([]string{"scope3"}))

	pu2, err := url.Parse(u2)
	if err != nil {
		t.Fatal(err)
	}

	scopes := strings.Split(pu2.Query().Get("scope"), " ")
	if len(scopes) != 2 {
		t.Errorf("want 2 scopes, found: %v", scopes)
	}
}
