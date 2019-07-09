package oidcserver

import (
	"context"
	"fmt"
	"net/http"
)

// newMockConnector returns a mock connector which requires no user interaction. It always returns
// the same (fake) identity.
func newMockConnector() Connector {
	return &mockConnector{
		Identity: Identity{
			UserID:        "0-385-28089-0",
			Username:      "Kilgore Trout",
			Email:         "kilgore@kilgore.trout",
			EmailVerified: true,
			Groups:        []string{"authors"},
			ConnectorData: connectorData,
		},
	}
}

var (
	_ Connector        = &mockConnector{}
	_ RefreshConnector = &mockConnector{}
)

type mockConnector struct {
	// The returned identity.
	Identity Identity

	auth Authenticator
}

func (m *mockConnector) Initialize(auth Authenticator) error {
	m.auth = auth
	return nil
}

func (m *mockConnector) LoginPage(w http.ResponseWriter, r *http.Request, lr LoginRequest) {
	// just auto mark the session as good, and redirect the user to the final page
	ret, err := m.auth.Authenticate(r.Context(), lr.AuthID, m.Identity)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal error: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

var connectorData = []byte("foobar")

// Refresh updates the identity during a refresh token request.
func (m *mockConnector) Refresh(ctx context.Context, s Scopes, identity Identity) (Identity, error) {
	return m.Identity, nil
}
