package oidcserver

import (
	"context"
	"net/http"
)

// Scopes represents additional data requested by the clients about the end user.
type Scopes struct {
	// The client has requested a refresh token from the server.
	OfflineAccess bool

	// The client has requested group information about the end user.
	Groups bool
}

// Identity represents the ID Token claims supported by the server.
type Identity struct {
	UserID        string
	Username      string
	Email         string
	EmailVerified bool

	Groups []string

	// ConnectorData holds data used by the connector for subsequent requests after initial
	// authentication, such as access tokens for upstream provides.
	//
	// This data is never shared with end users, OAuth clients, or through the API.
	ConnectorData []byte
}

// LoginRequest encapsulates the information passed in for this SSO request.
type LoginRequest struct {
	// AuthID is the unique identifier for this access request. It is assigned
	// at login request, and is needed to finalize the flow.
	AuthID string
	// Scopes are the Oauth2 Scopes for OIDC requests.
	Scopes Scopes
}

// Connector is used to actually manage the end user authentication
type Connector interface {
	// LoginPage is called at the start of an authentication flow. This method
	// can render/return whatever it wants and run the user through any
	// arbitrary intermediate pages. The only requirement is that it threads the
	// AuthID through these, and at the end of the connector flow it needs to
	// pass this to the Authenticator's Authenticate method, and redirect the
	// user to the resulting URL.
	LoginPage(w http.ResponseWriter, r *http.Request, lr LoginRequest)
}

// RefreshConnector is a connector that can update the client claims.
type RefreshConnector interface {
	// Refresh is called when a client attempts to claim a refresh token. The
	// connector should attempt to update the identity object to reflect any
	// changes since the token was last refreshed.
	Refresh(ctx context.Context, s Scopes, identity Identity) (Identity, error)
}
