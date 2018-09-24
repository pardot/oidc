// Package salesforce implements logging in through OpenID Connect providers.
package salesforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/heroku/deci/internal/connector"
)

var (
	_ connector.CallbackConnector = (*SalesforceConnector)(nil)
	_ connector.RefreshConnector  = (*SalesforceConnector)(nil)
)

type SalesforceConnector struct {
	redirectURI  string
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	ctx          context.Context
	cancel       context.CancelFunc
	logger       logrus.FieldLogger
	// groupMappings is a map of user ID to group membership
	groupMappings   map[string][]string
	permitUngrouped bool
}

func (c *SalesforceConnector) Close() error {
	c.cancel()
	return nil
}

func (c *SalesforceConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.oauth2Config.AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *SalesforceConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}
	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get token: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return identity, errors.New("oidc: no id_token in token response")
	}
	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to verify ID Token: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oaClient := c.oauth2Config.Client(ctx, token)

	sfdcUser, err := c.fetchIdentity(oaClient, idToken.Subject)
	if err != nil {
		return identity, errors.Wrap(err, "Error fetching user identity from Salesforce")
	}

	identity, err = c.mapUser(connector.Identity{}, sfdcUser, s.Groups)
	if err != nil {
		return identity, err
	}

	if s.OfflineAccess {
		data := connectorData{
			UserIDURL:    idToken.Subject,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, errors.Wrap(err, "Error serializing connector data")
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

// Refresh is implemented for backwards compatibility, even though it's a no-op.
func (c *SalesforceConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	if len(identity.ConnectorData) == 0 {
		return identity, errors.New("no refresh information found")
	}

	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, errors.Wrap(err, "Error unmarshaling connector data")
	}

	tok := &oauth2.Token{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		Expiry:       data.Expiry,
	}

	client := oauth2.NewClient(ctx, &notifyRefreshTokenSource{
		new: c.oauth2Config.TokenSource(ctx, tok),
		t:   tok,
		f: func(tok *oauth2.Token) error {
			data := connectorData{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				Expiry:       tok.Expiry,
				UserIDURL:    data.UserIDURL,
			}
			connData, err := json.Marshal(data)
			if err != nil {
				return errors.Wrap(err, "Error marshaling connector data")
			}
			identity.ConnectorData = connData
			return nil
		},
	})

	sfdcUser, err := c.fetchIdentity(client, data.UserIDURL)
	if err != nil {
		return identity, errors.Wrap(err, "Error re-fetching identity")
	}

	identity, err = c.mapUser(identity, sfdcUser, s.Groups)
	if err != nil {
		return identity, err
	}

	return identity, nil
}

// connectorData is persisted for our future use
type connectorData struct {
	UserIDURL    string    `json:"user_id_url"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Expiry       time.Time `json:"expiry"`
}

// SalesforceIdentity represents the data returned when fetching the user's
// identity URL. see
// https://help.salesforce.com/articleView?id=remoteaccess_using_openid.htm&type=5
// "Identity URL Response"
type SalesforceIdentity struct {
	// ID - Identity URL (the same URL that was queried)
	ID string `json:"id"`
	// AssertedUser - Boolean value indicating whether the specified access token was issued for this identity
	AssertedUser bool `json:"asserted_user"`
	// UserID - Salesforce user ID
	UserID string `json:"user_id"`
	// Username — Salesforce username
	Username string `json:"username"`
	// OrganizationID - Salesforce org ID
	OrganizationID string `json:"organization_id"`
	// NiceName — Community nickname of the queried user
	NickName string `json:"nick_name"`
	// DisplayName - Display name (full name) of the queried user
	DisplayName string `json:"display_name"`
	// Email — Email address of the queried user
	Email string `json:"email"`
	// EmailVerified — Indicates whether the user’s email was verified after the user clicked a link in an email confirmation message.
	EmailVerified bool `json:"email_verified"`
	// FirstName - First name of the user
	FirstName string `json:"first_name"`
	// LastName — Last name of the user
	LastName string `json:"last_name"`
	// Timezone — Time zone in the user’s settings
	Timezone string `json:"timezone"`
	// Status — User’s current Chatter status
	Status struct {
		CreatedDate interface{} `json:"created_date"`
		Body        interface{} `json:"body"`
	} `json:"status"`
	// Photos — Map of URLs to the user’s profile pictures
	Photos struct {
		Picture   string `json:"picture"`
		Thumbnail string `json:"thumbnail"`
	} `json:"photos"`
	// Active — Boolean specifying whether the queried user is active
	Active bool `json:"active"`
	// UserType — Type of the queried user
	UserType string `json:"user_type"`
	// Language — Queried user’s language
	Language string `json:"language"`
	// Locale — Queried user’s locale
	Locale string `json:"locale"`
	// UTCOffset — Offset from UTC of the time zone of the queried user, in milliseconds
	UTCOffset int `json:"utcOffset"`
	// LastModifiedDate — xsd datetime format of the last modification of the user, for example, 2010-06-28T20:54:09.000Z
	LastModifiedDate string `json:"last_modified_date"`
}

// fetchIdentity takes the URL from the token's subject, and returns the
// information about the user
func (c *SalesforceConnector) fetchIdentity(httpClient *http.Client, userIDUrl string) (*SalesforceIdentity, error) {
	req, err := http.NewRequest("GET", userIDUrl, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating identity fetch request")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Error fetching user %s identity", userIDUrl)
	}
	defer resp.Body.Close()

	id := SalesforceIdentity{}

	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return nil, errors.Wrapf(err, "Error JSON decoding identity response for %s", userIDUrl)
	}

	return &id, err
}

// mapUser will take the given identity and salesforce user, and validate it and
// return a new identity
func (c *SalesforceConnector) mapUser(identity connector.Identity, user *SalesforceIdentity, groups bool) (connector.Identity, error) {
	if !user.Active {
		return identity, fmt.Errorf("User %s no longer active", user.ID)
	}

	// get the user's group info
	grp, ok := c.groupMappings[user.UserID]

	if !c.permitUngrouped && !ok {
		return identity, fmt.Errorf("User %s does not exist in group mapping file", user.UserID)
	}

	if groups && ok {
		identity.Groups = grp
	}

	if groups && !ok {
		c.logger.WithField("user", user.UserID).Warn("No groups found for user, but groups requested")
	}

	identity.UserID = user.UserID
	identity.Username = user.DisplayName
	identity.Email = user.Email
	identity.EmailVerified = user.EmailVerified

	return identity, nil
}

type tokenNotifyFunc func(*oauth2.Token) error

// notifyRefreshTokenSource is essentially `oauth2.ResuseTokenSource` with `TokenNotifyFunc` added.
type notifyRefreshTokenSource struct {
	new oauth2.TokenSource
	mu  sync.Mutex // guards t
	t   *oauth2.Token
	f   tokenNotifyFunc // called when token refreshed so new refresh token can be persisted
}

// Token returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s *notifyRefreshTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, s.f(t)
}
