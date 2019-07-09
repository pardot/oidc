package oidcserver

import (
	"context"
	"fmt"
	"path"

	storagepb "github.com/heroku/deci/proto/deci/storage/v1beta1"
)

// authenticator is passed to connectors to allow them to mark users as
// authenticated, and provide their information. It's basically a thin
// wrapper for the main Server type, to avoid exposing the Authenticate
// method on server's public type
type authenticator struct {
	s *Server
}

// finalizeLogin associates the user's identity with the current AuthRequest, then returns
// the approval page's path.
// TODO(lstoll) - this becomes the authorizer methd
func (a *authenticator) Authenticate(ctx context.Context, authID string, ident Identity) (returnURL string, err error) {
	// func (s *Server) finalizeLogin(ctx context.Context, identity Identity, authReq *storagepb.AuthRequest, authReqVers string) (string, error) {
	claims := &storagepb.Claims{
		UserId:        ident.UserID,
		Username:      ident.Username,
		Email:         ident.Email,
		EmailVerified: ident.EmailVerified,
		Groups:        ident.Groups,
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

	return path.Join(a.s.issuerURL.Path, "/approval") + "?req=" + authReq.Id, nil
}
