package salesforce

import (
	"context"
	"fmt"
	"sync"

	oidc "github.com/coreos/go-oidc"
	"github.com/heroku/deci/internal/connector"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// Config holds configuration options for OpenID Connect logins.
type Config struct {
	// Issuer (salesforce instance domain, or login.salesforce.com)
	Issuer string `json:"issuer"`
	// ClientID for oauth2 request
	ClientID string `json:"clientID"`
	// ClientSecret for oauth2 request
	ClientSecret string `json:"clientSecret"`
	// URI for oauth2 redirect
	RedirectURI string `json:"redirectURI"`
	// Scopes to request, defaults to profile and email
	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// PermitUngrouped will allow users not explicitly listed in the config
	// through, they will just have no group claims.
	PermitUngrouped bool `json:"permit_ungrouped"`

	// GroupFile is the path to the file containing user/group mappings
	GroupFile string `json:"group_file"`
}

// Open returns a connector which can be used to login users through an upstream
// OpenID Connect provider.
func (c *Config) Open(id string, logger logrus.FieldLogger) (conn connector.Connector, err error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("Client ID and/or secret empty, these are required")
	}

	// go-oidc uses this context _for all subsequent key fetches_, so if we
	// cancel it will forever fail. at some point this needs to be improved
	// upstream
	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// always register as broken, salesforce always is
	registerBrokenAuthHeaderProvider(provider.Endpoint().TokenURL)

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email")
	}

	m, err := LoadMappings(c.GroupFile)
	if err != nil {
		cancel()
		return nil, errors.Wrap(err, "Error loading mappings")
	}

	return &SalesforceConnector{
		redirectURI: c.RedirectURI,
		oauth2Config: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{ClientID: c.ClientID},
		),
		logger:          logger,
		cancel:          cancel,
		groupMappings:   m,
		permitUngrouped: c.PermitUngrouped,
	}, nil
}

// golang.org/x/oauth2 doesn't do internal locking. Need to do it in this
// package ourselves and hope that other packages aren't calling it at the
// same time.
var registerMu = new(sync.Mutex)

func registerBrokenAuthHeaderProvider(url string) {
	registerMu.Lock()
	defer registerMu.Unlock()

	oauth2.RegisterBrokenAuthHeaderProvider(url)
}
