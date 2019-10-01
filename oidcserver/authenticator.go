package oidcserver

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/wrappers"
	storagepb "github.com/pardot/deci/proto/deci/storage/v1beta1"
)

// Authenticator is capable of associating the user's identity with a given
// authID, then returning the final redirect URL. This is the primary way a
// Connector calls back to Server to finalize the flow.
type Authenticator interface {
	// Authenticate associates the user's identity with the given authID, then
	// returns final redirect URL.
	Authenticate(ctx context.Context, authID string, ident Identity) (returnURL string, err error)

	// LoginRequest loads the login request information for a given authID.
	LoginRequest(ctx context.Context, authID string) (LoginRequest, error)
}

// authenticator is a thin wrapper for the main Server type, to avoid exposing
// the Authenticate method on server's public type.
type authenticator struct {
	s *Server
}

func (a *authenticator) Authenticate(ctx context.Context, authID string, ident Identity) (returnURL string, err error) {
	claims := &storagepb.Claims{
		UserId:        ident.UserID,
		Username:      ident.Username,
		Email:         ident.Email,
		EmailVerified: ident.EmailVerified,
		Groups:        ident.Groups,
		Amr:           ident.AMR,
	}
	if ident.ACR != nil {
		claims.Acr = &wrappers.StringValue{Value: *ident.ACR}
	}

	authReq := &storagepb.AuthRequest{}
	authReqVers, err := a.s.storage.Get(ctx, authReqKeyspace, authID, authReq)
	if err != nil {
		return "", err
	}

	authReq.LoggedIn = true
	authReq.Claims = claims
	authReq.ConnectorData = ident.ConnectorData

	if _, err := a.s.storage.Put(ctx, authReqKeyspace, authReq.Id, authReqVers, authReq); err != nil {
		return "", fmt.Errorf("failed to update auth request: %v", err)
	}

	email := claims.Email
	if !claims.EmailVerified {
		email = email + " (unverified)"
	}

	a.s.logger.Infof("login successful: connector %q, username=%q, email=%q, groups=%q",
		authReq.ConnectorId, claims.Username, email, claims.Groups)

	return a.s.absURL("/approval") + "?req=" + authReq.Id, nil
}

func (a *authenticator) LoginRequest(ctx context.Context, authID string) (LoginRequest, error) {
	authReq := &storagepb.AuthRequest{}
	_, err := a.s.storage.Get(ctx, authReqKeyspace, authID, authReq)
	if err != nil {
		return LoginRequest{}, err
	}

	return LoginRequest{
		AuthID: authID,
		Scopes: parseScopes(authReq.Scopes),
	}, nil
}
