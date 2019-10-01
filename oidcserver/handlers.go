package oidcserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/golang/protobuf/ptypes"
	"github.com/gorilla/mux"
	"github.com/pardot/deci/oidcserver/internal"
	storagepb "github.com/pardot/deci/proto/deci/storage/v1beta1"
	"github.com/pardot/deci/storage"
	jose "gopkg.in/square/go-jose.v2"
)

func (s *Server) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.signer.PublicKeys(r.Context())
	if err != nil {
		s.logger.WithError(err).Error("failed to fetch public keys")
		s.renderError(w, http.StatusInternalServerError, "Internal server error.")
		return
	}

	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		s.logger.Errorf("failed to marshal discovery data: %v", err)
		s.renderError(w, http.StatusInternalServerError, "Internal server error.")
		return
	}

	// TODO(lstoll): is it worth setting a better time for this, and caching here?
	maxAge := 1 * time.Minute

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", int(maxAge.Seconds())))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if _, err := w.Write(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type discovery struct {
	Issuer        string   `json:"issuer"`
	Auth          string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	UserInfo      string   `json:"userinfo_endpoint"`
	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
	Scopes        []string `json:"scopes_supported"`
	AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	Claims        []string `json:"claims_supported"`
}

func (s *Server) discoveryHandler() (http.HandlerFunc, error) {
	d := discovery{
		Issuer:      s.issuerURL.String(),
		Auth:        s.absURL("/auth"),
		Token:       s.absURL("/token"),
		Keys:        s.absURL("/keys"),
		UserInfo:    s.absURL("/userinfo"),
		Subjects:    []string{"public"},
		IDTokenAlgs: []string{string(jose.RS256)},
		Scopes:      []string{"openid", "email", "groups", "profile", "offline_access"},
		AuthMethods: []string{"client_secret_basic"},
		Claims: []string{
			"aud", "email", "email_verified", "exp",
			"iat", "iss", "locale", "name", "sub",
		},
	}

	for responseType := range s.supportedResponseTypes {
		d.ResponseTypes = append(d.ResponseTypes, responseType)
	}
	sort.Strings(d.ResponseTypes)

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discovery data: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if _, err := w.Write(data); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}), nil
}

// handleAuthorization handles the OAuth2 auth endpoint.
func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	authReq, err := s.parseAuthorizationRequest(r)
	if err != nil {
		s.logger.Errorf("Failed to parse authorization request: %v", err)
		if handler, ok := err.Handle(); ok {
			// client_id and redirect_uri checked out and we can redirect back to
			// the client with the error.
			handler.ServeHTTP(w, r)
			return
		}

		// Otherwise render the error to the user.
		//
		// TODO(ericchiang): Should we just always render the error?
		s.renderError(w, err.Status(), err.Error())
		return
	}

	// TODO(ericchiang): Create this authorization request later in the login flow
	// so users don't hit "not found" database errors if they wait at the login
	// screen too long.
	//
	// See: https://github.com/dexidp/dex/issues/646
	var perr error
	authExp := s.now().Add(s.authRequestsValidFor)
	authReq.Expiry, perr = ptypes.TimestampProto(authExp)
	if perr != nil {
		s.logger.Errorf("Failed to convert timestamp: %v", err)
		s.renderError(w, http.StatusInternalServerError, "Internal Error.")
		return
	}
	if _, err := s.storage.PutWithExpiry(r.Context(), authReqKeyspace, authReq.Id, 0, authReq, authExp); err != nil {
		s.logger.Errorf("Failed to create authorization request: %v", err)
		s.renderError(w, http.StatusInternalServerError, "Failed to connect to the database.")
		return
	}

	if len(s.connectors) == 1 {
		for k := range s.connectors {
			// TODO(ericchiang): Make this pass on r.URL.RawQuery and let something latter
			// on create the auth request.
			http.Redirect(w, r, s.absPath("/auth", k)+"?req="+authReq.Id, http.StatusFound)
			return
		}
	}

	connectorInfos := make([]connectorInfo, len(s.connectors))
	i := 0
	for k := range s.connectors {
		connectorInfos[i] = connectorInfo{
			ID:   k,
			Name: k,
			// TODO(ericchiang): Make this pass on r.URL.RawQuery and let something latter
			// on create the auth request.
			URL: s.absPath("/auth", k) + "?req=" + authReq.Id,
		}
		i++
	}

	if err := s.templates.login(w, connectorInfos); err != nil {
		s.logger.Errorf("Server template error: %v", err)
	}
}

func (s *Server) handleConnectorLogin(w http.ResponseWriter, r *http.Request) {
	connID := mux.Vars(r)["connector"]
	conn, ok := s.connectors[connID]
	if !ok {
		s.logger.Error("Failed to create authorization request: connector does not exist")
		s.renderError(w, http.StatusNotFound, "Requested resource does not exist")
		return
	}

	authReqID := r.FormValue("req")

	authReq := &storagepb.AuthRequest{}
	authReqVers, err := s.storage.Get(r.Context(), authReqKeyspace, authReqID, authReq)
	if err != nil {
		s.logger.Errorf("Failed to get auth request: %v", err)
		if storage.IsNotFoundErr(err) {
			s.renderError(w, http.StatusBadRequest, "Login session expired.")
		} else {
			s.renderError(w, http.StatusInternalServerError, "Database error.")
		}
		return
	}

	// Set the connector being used for the login.
	if authReq.ConnectorId != connID {
		authReq.ConnectorId = connID
		_, err = s.storage.Put(r.Context(), authReqKeyspace, authReqID, authReqVers, authReq)
		if err != nil {
			s.logger.Errorf("Failed to set connector ID on auth request: %v", err)
			s.renderError(w, http.StatusInternalServerError, "Database error.")
			return
		}
	}

	lr := LoginRequest{
		AuthID:    authReqID,
		Scopes:    parseScopes(authReq.Scopes),
		ACRValues: authReq.AcrValues,
	}

	conn.LoginPage(w, r, lr)
}

func (s *Server) handleApproval(w http.ResponseWriter, r *http.Request) {
	authReq := &storagepb.AuthRequest{}
	_, err := s.storage.Get(r.Context(), authReqKeyspace, r.FormValue("req"), authReq)
	if err != nil {
		s.logger.Errorf("Failed to get auth request: %v", err)
		s.renderError(w, http.StatusInternalServerError, "Database error.")
		return
	}
	if !authReq.LoggedIn {
		s.logger.Errorf("Auth request does not have an identity for approval")
		s.renderError(w, http.StatusInternalServerError, "Login process not yet finalized.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if s.skipApproval {
			s.sendCodeResponse(w, r, authReq)
			return
		}
		client, err := s.clients.GetClient(authReq.ClientId)
		if err != nil {
			s.logger.Errorf("Failed to get client %q: %v", authReq.ClientId, err)
			s.renderError(w, http.StatusInternalServerError, "Failed to retrieve client.")
			return
		}
		if err := s.templates.approval(w, authReq.Id, authReq.Claims.Username, client.Name, authReq.Scopes); err != nil {
			s.logger.Errorf("Server template error: %v", err)
		}
	case http.MethodPost:
		if r.FormValue("approval") != "approve" {
			s.renderError(w, http.StatusInternalServerError, "Approval rejected.")
			return
		}
		s.sendCodeResponse(w, r, authReq)
	}
}

func (s *Server) sendCodeResponse(w http.ResponseWriter, r *http.Request, authReq *storagepb.AuthRequest) {
	arexp, err := ptypes.Timestamp(authReq.Expiry)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Internal server error.")
		return
	}
	if s.now().After(arexp) {
		s.renderError(w, http.StatusBadRequest, "User session has expired.")
		return
	}

	if err := s.storage.Delete(r.Context(), authReqKeyspace, authReq.Id); err != nil {
		if !storage.IsNotFoundErr(err) {
			s.logger.Errorf("Failed to delete authorization request: %v", err)
			s.renderError(w, http.StatusInternalServerError, "Internal server error.")
		} else {
			s.renderError(w, http.StatusBadRequest, "User session error.")
		}
		return
	}
	u, err := url.Parse(authReq.RedirectUri)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Invalid redirect URI.")
		return
	}

	var (
		// Was the initial request using the implicit or hybrid flow instead of
		// the "normal" code flow?
		implicitOrHybrid = false

		// Only present in hybrid or code flow. code.ID == "" if this is not set.
		code *storagepb.AuthCode = &storagepb.AuthCode{}

		// ID token returned immediately if the response_type includes "id_token".
		// Only valid for implicit and hybrid flows.
		idToken       string
		idTokenExpiry time.Time

		// Access token
		accessToken string
	)

	for _, responseType := range authReq.ResponseTypes {
		switch responseType {
		case responseTypeCode:
			exp := s.now().Add(time.Minute * 30)
			expTS, err := ptypes.TimestampProto(exp)
			if err != nil {
				s.renderError(w, http.StatusInternalServerError, "Internal Error.")
				return
			}
			code = &storagepb.AuthCode{
				Id:            storage.NewID(),
				ClientId:      authReq.ClientId,
				ConnectorId:   authReq.ConnectorId,
				Nonce:         authReq.Nonce,
				Scopes:        authReq.Scopes,
				Claims:        authReq.Claims,
				Expiry:        expTS,
				RedirectUri:   authReq.RedirectUri,
				ConnectorData: authReq.ConnectorData,
			}
			if _, err := s.storage.PutWithExpiry(r.Context(), authCodeKeyspace, code.Id, 0, code, exp); err != nil {
				s.logger.Errorf("Failed to create auth code: %v", err)
				s.renderError(w, http.StatusInternalServerError, "Internal server error.")
				return
			}

			// Implicit and hybrid flows that try to use the OOB redirect URI are
			// rejected earlier. If we got here we're using the code flow.
			if authReq.RedirectUri == redirectURIOOB {
				if err := s.templates.oob(w, code.Id); err != nil {
					s.logger.Errorf("Server template error: %v", err)
				}
				return
			}
		case responseTypeToken:
			implicitOrHybrid = true
		case responseTypeIDToken:
			implicitOrHybrid = true
			var err error

			accessToken, err = s.newAccessToken(authReq.ClientId, authReq.Claims, authReq.Scopes, authReq.Nonce, authReq.ConnectorId)
			if err != nil {
				s.logger.Errorf("failed to create new access token: %v", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				return
			}

			idToken, idTokenExpiry, err = s.newIDToken(authReq.ClientId, authReq.Claims, authReq.Scopes, authReq.Nonce, accessToken, authReq.ConnectorId)
			if err != nil {
				s.logger.Errorf("failed to create ID token: %v", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				return
			}
		}
	}

	if implicitOrHybrid {
		v := url.Values{}
		v.Set("access_token", accessToken)
		v.Set("token_type", "bearer")
		v.Set("state", authReq.State)
		if idToken != "" {
			v.Set("id_token", idToken)
			// The hybrid flow with only "code token" or "code id_token" doesn't return an
			// "expires_in" value. If "code" wasn't provided, indicating the implicit flow,
			// don't add it.
			//
			// https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthResponse
			if code.Id == "" {
				v.Set("expires_in", strconv.Itoa(int(idTokenExpiry.Sub(s.now()).Seconds())))
			}
		}
		if code.Id != "" {
			v.Set("code", code.Id)
		}

		// Implicit and hybrid flows return their values as part of the fragment.
		//
		//   HTTP/1.1 303 See Other
		//   Location: https://client.example.org/cb#
		//     access_token=SlAV32hkKG
		//     &token_type=bearer
		//     &id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
		//     &expires_in=3600
		//     &state=af0ifjsldkj
		//
		u.Fragment = v.Encode()
	} else {
		// The code flow add values to the URL query.
		//
		//   HTTP/1.1 303 See Other
		//   Location: https://client.example.org/cb?
		//     code=SplxlOBeZQQYbYS6WxSbIA
		//     &state=af0ifjsldkj
		//
		q := u.Query()
		q.Set("code", code.Id)
		q.Set("state", authReq.State)
		u.RawQuery = q.Encode()
	}

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		var err error
		if clientID, err = url.QueryUnescape(clientID); err != nil {
			s.tokenErrHelper(w, errInvalidRequest, "client_id improperly encoded", http.StatusBadRequest)
			return
		}
		if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
			s.tokenErrHelper(w, errInvalidRequest, "client_secret improperly encoded", http.StatusBadRequest)
			return
		}
	} else {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}

	client, err := s.clients.GetClient(clientID)
	if err != nil {
		if !isNoSuchClientErr(err) {
			s.logger.Errorf("failed to get client: %v", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		} else {
			s.tokenErrHelper(w, errInvalidClient, "Invalid client credentials.", http.StatusUnauthorized)
		}
		return
	}
	if client.Secret != clientSecret {
		s.tokenErrHelper(w, errInvalidClient, "Invalid client credentials.", http.StatusUnauthorized)
		return
	}

	grantType := r.PostFormValue("grant_type")
	switch grantType {
	case grantTypeAuthorizationCode:
		s.handleAuthCode(w, r, client)
	case grantTypeRefreshToken:
		s.handleRefreshToken(w, r, client)
	default:
		s.tokenErrHelper(w, errInvalidGrant, "", http.StatusBadRequest)
	}
}

// handle an access token request https://tools.ietf.org/html/rfc6749#section-4.1.3
func (s *Server) handleAuthCode(w http.ResponseWriter, r *http.Request, client *Client) {
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")

	authCode := &storagepb.AuthCode{}
	_, err := s.storage.Get(r.Context(), authCodeKeyspace, code, authCode)
	if err != nil {
		if !storage.IsNotFoundErr(err) {
			s.logger.Errorf("failed to get auth code: %v", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		} else {
			s.tokenErrHelper(w, errInvalidRequest, "Invalid or expired code parameter.", http.StatusBadRequest)
		}
		return
	}
	authCodeExp, err := ptypes.Timestamp(authCode.Expiry)
	if err != nil || s.now().After(authCodeExp) || authCode.ClientId != client.ID {
		s.tokenErrHelper(w, errInvalidRequest, "Invalid or expired code parameter.", http.StatusBadRequest)
		return
	}

	if authCode.RedirectUri != redirectURI {
		s.tokenErrHelper(w, errInvalidRequest, "redirect_uri did not match URI from initial request.", http.StatusBadRequest)
		return
	}

	accessToken, err := s.newAccessToken(client.ID, authCode.Claims, authCode.Scopes, authCode.Nonce, authCode.ConnectorId)
	if err != nil {
		s.logger.Errorf("failed to create new access token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	idToken, expiry, err := s.newIDToken(client.ID, authCode.Claims, authCode.Scopes, authCode.Nonce, accessToken, authCode.ConnectorId)
	if err != nil {
		s.logger.Errorf("failed to create ID token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	if err := s.storage.Delete(r.Context(), authCodeKeyspace, code); err != nil {
		s.logger.Errorf("failed to delete auth code: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	reqRefresh := func() bool {
		// Ensure the connector supports refresh tokens.
		//
		// Connectors like `saml` do not implement RefreshConnector.
		conn, ok := s.connectors[authCode.ConnectorId]
		if !ok {
			s.logger.Errorf("connector with ID %q not found: %v", authCode.ConnectorId, err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return false
		}

		_, ok = conn.(RefreshConnector)
		if !ok {
			return false
		}

		for _, scope := range authCode.Scopes {
			if scope == scopeOfflineAccess {
				return true
			}
		}
		return false
	}()
	var refreshToken string
	if reqRefresh {
		nowts, err := ptypes.TimestampProto(s.now())
		if err != nil {
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}
		refresh := &storagepb.RefreshToken{
			Id:            storage.NewID(),
			Token:         storage.NewID(),
			ClientId:      authCode.ClientId,
			ConnectorId:   authCode.ConnectorId,
			Scopes:        authCode.Scopes,
			Claims:        authCode.Claims,
			Nonce:         authCode.Nonce,
			ConnectorData: authCode.ConnectorData,
			CreatedAt:     nowts,
			LastUsed:      nowts,
		}
		token := &internal.RefreshToken{
			RefreshId: refresh.Id,
			Token:     refresh.Token,
		}
		if refreshToken, err = internal.Marshal(token); err != nil {
			s.logger.Errorf("failed to marshal refresh token: %v", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}

		if _, err := s.storage.Put(r.Context(), refreshTokenKeyspace, refresh.Id, 0, refresh); err != nil {
			s.logger.Errorf("failed to create refresh token: %v", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}

		// deleteToken determines if we need to delete the newly created refresh token
		// due to a failure in updating/creating the OfflineSession object for the
		// corresponding user.
		var deleteToken bool
		defer func() {
			if deleteToken {
				// Delete newly created refresh token from storage.
				if err := s.storage.Delete(r.Context(), refreshTokenKeyspace, refresh.Id); err != nil {
					s.logger.Errorf("failed to delete refresh token: %v", err)
					s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
					return
				}
			}
		}()

		tokenRef := &storagepb.RefreshTokenRef{
			Id:        refresh.Id,
			ClientId:  refresh.ClientId,
			CreatedAt: refresh.CreatedAt,
			LastUsed:  refresh.LastUsed,
		}

		// Try to retrieve an existing OfflineSession object for the corresponding user.
		session := &storagepb.OfflineSessions{}
		if sessVer, err := s.storage.Get(r.Context(), offlineSessionsKeyspace, offlineSessionID(refresh.Claims.UserId, refresh.ConnectorId), session); err != nil {
			if !storage.IsNotFoundErr(err) {
				s.logger.Errorf("failed to get offline session: %v", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}
			offlineSessions := &storagepb.OfflineSessions{
				UserId:  refresh.Claims.UserId,
				ConnId:  refresh.ConnectorId,
				Refresh: make(map[string]*storagepb.RefreshTokenRef),
			}
			offlineSessions.Refresh[tokenRef.ClientId] = tokenRef

			// Create a new OfflineSession object for the user and add a reference object for
			// the newly received refreshtoken.
			if _, err := s.storage.Put(r.Context(), offlineSessionsKeyspace, offlineSessionID(refresh.Claims.UserId, refresh.ConnectorId), 0, offlineSessions); err != nil {
				s.logger.Errorf("failed to create offline session: %v", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}
		} else {
			if oldTokenRef, ok := session.Refresh[tokenRef.ClientId]; ok {
				// Delete old refresh token from storage.
				if err := s.storage.Delete(r.Context(), refreshTokenKeyspace, oldTokenRef.Id); err != nil {
					s.logger.Errorf("failed to delete refresh token: %v", err)
					s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
					deleteToken = true
					return
				}
			}

			// Update existing OfflineSession obj with new RefreshTokenRef.
			session.Refresh[tokenRef.ClientId] = tokenRef
			if _, err := s.storage.Put(r.Context(), offlineSessionsKeyspace, offlineSessionID(refresh.Claims.UserId, refresh.ConnectorId), sessVer, session); err != nil {
				s.logger.Errorf("failed to update offline session: %v", err)
				s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
				deleteToken = true
				return
			}

		}
	}
	s.writeAccessToken(w, idToken, accessToken, refreshToken, expiry)
}

// handle a refresh token request https://tools.ietf.org/html/rfc6749#section-6
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request, client *Client) {
	code := r.PostFormValue("refresh_token")
	scope := r.PostFormValue("scope")
	if code == "" {
		s.tokenErrHelper(w, errInvalidRequest, "No refresh token in request.", http.StatusBadRequest)
		return
	}

	token := new(internal.RefreshToken)
	if err := internal.Unmarshal(code, token); err != nil {
		// For backward compatibility, assume the refresh_token is a raw refresh token ID
		// if it fails to decode.
		//
		// Because refresh_token values that aren't unmarshable were generated by servers
		// that don't have a Token value, we'll still reject any attempts to claim a
		// refresh_token twice.
		token = &internal.RefreshToken{RefreshId: code, Token: ""}
	}

	refresh := &storagepb.RefreshToken{}
	refreshVers, err := s.storage.Get(r.Context(), refreshTokenKeyspace, token.RefreshId, refresh)
	if err != nil {
		s.logger.Errorf("failed to get refresh token: %v", err)
		if storage.IsNotFoundErr(err) {
			s.tokenErrHelper(w, errInvalidRequest, "Refresh token is invalid or has already been claimed by another client.", http.StatusBadRequest)
		} else {
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		}
		return
	}
	if refresh.ClientId != client.ID {
		s.logger.Errorf("client %s trying to claim token for client %s", client.ID, refresh.ClientId)
		s.tokenErrHelper(w, errInvalidRequest, "Refresh token is invalid or has already been claimed by another client.", http.StatusBadRequest)
		return
	}
	if refresh.Token != token.Token {
		s.logger.Errorf("refresh token with id %s claimed twice", refresh.Id)
		s.tokenErrHelper(w, errInvalidRequest, "Refresh token is invalid or has already been claimed by another client.", http.StatusBadRequest)
		return
	}

	// Per the OAuth2 spec, if the client has omitted the scopes, default to the original
	// authorized scopes.
	//
	// https://tools.ietf.org/html/rfc6749#section-6
	scopes := refresh.Scopes
	if scope != "" {
		requestedScopes := strings.Fields(scope)
		var unauthorizedScopes []string

		for _, s := range requestedScopes {
			contains := func() bool {
				for _, scope := range refresh.Scopes {
					if s == scope {
						return true
					}
				}
				return false
			}()
			if !contains {
				unauthorizedScopes = append(unauthorizedScopes, s)
			}
		}

		if len(unauthorizedScopes) > 0 {
			msg := fmt.Sprintf("Requested scopes contain unauthorized scope(s): %q.", unauthorizedScopes)
			s.tokenErrHelper(w, errInvalidRequest, msg, http.StatusBadRequest)
			return
		}
		scopes = requestedScopes
	}

	conn, ok := s.connectors[refresh.ConnectorId]
	if !ok {
		s.logger.Errorf("connector with ID %q not found", refresh.ConnectorId)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	ident := Identity{
		UserID:        refresh.Claims.UserId,
		Username:      refresh.Claims.Username,
		Email:         refresh.Claims.Email,
		EmailVerified: refresh.Claims.EmailVerified,
		Groups:        refresh.Claims.Groups,
		ConnectorData: refresh.ConnectorData,
	}

	// Can the connector refresh the identity? If so, attempt to refresh the data
	// in the connector.
	//
	// TODO(ericchiang): We may want a strict mode where connectors that don't implement
	// this interface can't perform refreshing.
	if refreshConn, ok := conn.(RefreshConnector); ok {
		newIdent, err := refreshConn.Refresh(r.Context(), parseScopes(scopes), ident)
		if err != nil {
			s.logger.Errorf("failed to refresh identity: %v", err)
			s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
			return
		}
		ident = newIdent
	}

	claims := &storagepb.Claims{
		UserId:        ident.UserID,
		Username:      ident.Username,
		Email:         ident.Email,
		EmailVerified: ident.EmailVerified,
		Groups:        ident.Groups,
	}

	accessToken, err := s.newAccessToken(client.ID, claims, scopes, refresh.Nonce, refresh.ConnectorId)
	if err != nil {
		s.logger.Errorf("failed to create new access token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	idToken, expiry, err := s.newIDToken(client.ID, claims, scopes, refresh.Nonce, accessToken, refresh.ConnectorId)
	if err != nil {
		s.logger.Errorf("failed to create ID token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	newToken := &internal.RefreshToken{
		RefreshId: refresh.Id,
		Token:     storage.NewID(),
	}
	rawNewToken, err := internal.Marshal(newToken)
	if err != nil {
		s.logger.Errorf("failed to marshal refresh token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	lastUsed, err := ptypes.TimestampProto(s.now())
	if err != nil {
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	// Update LastUsed time stamp in refresh token reference object
	// in offline session for the user.
	offlineSession := &storagepb.OfflineSessions{}
	offlineSessionVers, err := s.storage.Get(r.Context(), offlineSessionsKeyspace, offlineSessionID(refresh.Claims.UserId, refresh.ConnectorId), offlineSession)
	if err != nil {
		s.logger.Errorf("failed to fetch offline session for update: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	if offlineSession.Refresh[refresh.ClientId].Id != refresh.Id {
		s.tokenErrHelper(w, errServerError, "Offline Session Invalid", http.StatusInternalServerError)
		return
	}
	offlineSession.Refresh[refresh.ClientId].LastUsed = lastUsed
	if _, err := s.storage.Put(r.Context(), offlineSessionsKeyspace, offlineSessionID(refresh.Claims.UserId, refresh.ConnectorId), offlineSessionVers, offlineSession); err != nil {
		s.logger.Errorf("failed to update offline session: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	refresh.Token = newToken.Token
	// Update the claims of the refresh token.
	//
	// UserID intentionally ignored for now.
	refresh.Claims.Username = ident.Username
	refresh.Claims.Email = ident.Email
	refresh.Claims.EmailVerified = ident.EmailVerified
	refresh.Claims.Groups = ident.Groups
	refresh.ConnectorData = ident.ConnectorData
	refresh.LastUsed = lastUsed

	// Update refresh token in the storage.
	if _, err := s.storage.Put(r.Context(), refreshTokenKeyspace, refresh.Id, refreshVers, refresh); err != nil {
		if storage.IsConflictErr(err) {
			s.tokenErrHelper(w, errServerError, "refresh token claimed twice", http.StatusInternalServerError)
			return
		}
		s.logger.Errorf("failed to update refresh token: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	s.writeAccessToken(w, idToken, accessToken, rawNewToken, expiry)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "

	auth := r.Header.Get("authorization")
	if len(auth) < len(prefix) || !strings.EqualFold(prefix, auth[:len(prefix)]) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.tokenErrHelper(w, errAccessDenied, "Invalid bearer token.", http.StatusUnauthorized)
		return
	}
	rawIDToken := auth[len(prefix):]

	verifier := oidc.NewVerifier(s.issuerURL.String(), s.signer, &oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		s.tokenErrHelper(w, errAccessDenied, err.Error(), http.StatusForbidden)
		return
	}

	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		s.tokenErrHelper(w, errServerError, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(claims); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *Server) writeAccessToken(w http.ResponseWriter, idToken, accessToken, refreshToken string, expiry time.Time) {
	resp := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IDToken      string `json:"id_token"`
	}{
		accessToken,
		"bearer",
		int(expiry.Sub(s.now()).Seconds()),
		refreshToken,
		idToken,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		s.logger.Errorf("failed to marshal access token response: %v", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if _, err := w.Write(data); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *Server) renderError(w http.ResponseWriter, status int, description string) {
	if err := s.templates.err(w, status, description); err != nil {
		s.logger.Errorf("Server template error: %v", err)
	}
}

func (s *Server) tokenErrHelper(w http.ResponseWriter, typ string, description string, statusCode int) {
	if err := tokenErr(w, typ, description, statusCode); err != nil {
		s.logger.Errorf("token error response: %v", err)
	}
}

func offlineSessionID(userID, connID string) string {
	return fmt.Sprintf(
		"%s-%s",
		base64.StdEncoding.EncodeToString([]byte(userID)),
		base64.StdEncoding.EncodeToString([]byte(connID)),
	)
}
