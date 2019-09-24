package oidcserver

import "fmt"

// Client represents an OAuth2 client.
//
// For further reading see:
//   * Trusted peers: https://developers.google.com/identity/protocols/CrossClientAuth
//   * Public clients: https://developers.google.com/api-client-library/python/auth/installed-app
type Client struct {
	// Client ID and secret used to identify the client.
	ID     string `json:"id" yaml:"id"`
	Secret string `json:"secret" yaml:"secret"`

	// A registered set of redirect URIs. When redirecting from dex to the client, the URI
	// requested to redirect to MUST match one of these values, unless the client is "public".
	RedirectURIs []string `json:"redirectURIs" yaml:"redirectURIs"`

	// TrustedPeers are a list of peers which can issue tokens on this client's behalf using
	// the dynamic "oauth2:server:client_id:(client_id)" scope. If a peer makes such a request,
	// this client's ID will appear as the ID Token's audience.
	//
	// Clients inherently trust themselves.
	TrustedPeers []string `json:"trustedPeers" yaml:"trustedPeers"`

	// Public clients must use either use a redirectURL 127.0.0.1:X or "urn:ietf:wg:oauth:2.0:oob"
	Public bool `json:"public" yaml:"public"`

	// Name and LogoURL used when displaying this client to the end user.
	Name    string `json:"name" yaml:"name"`
	LogoURL string `json:"logoURL" yaml:"logoURL"`
}

// ClientSource can be queried to get information about an oauth2 client.
type ClientSource interface {
	// GetClient returns information about the given client ID. It will be
	// called for each lookup. If the client is not found but no other error
	// occurred, an ErrNoSuchClient should be returned
	GetClient(id string) (*Client, error)
}

// StaticClientSource is a ClientSource backed by a static map of clients.
type StaticClientSource map[string]*Client

// NewStaticClientSource creates a StaticClientSource from a list of clients.
func NewStaticClientSource(clients []*Client) StaticClientSource {
	m := make(map[string]*Client)
	for _, c := range clients {
		m[c.ID] = c
	}

	return StaticClientSource(m)
}

func (s StaticClientSource) GetClient(id string) (*Client, error) {
	client, ok := s[id]
	if !ok {
		return nil, noSuchClientError(fmt.Sprintf("client %q does not exist", id))
	}

	return client, nil
}

// ErrNoSuchClient indicates that the requested client does not exist
type ErrNoSuchClient interface {
	NoSuchClient()
}

type noSuchClientError string

func (e noSuchClientError) Error() string {
	return string(e)
}

func (e noSuchClientError) NoSuchClient() {
}

func isNoSuchClientErr(err error) bool {
	_, ok := err.(ErrNoSuchClient)
	return ok
}
