package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pardot/oidc"
	"github.com/pardot/oidc/oauth2"
	corev1beta1 "github.com/pardot/oidc/proto/core/v1beta1"
)

func TestStartAuthorization(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"
	)

	clientSource := &stubCS{
		validClients: map[string]csClient{
			clientID: csClient{
				Secret:      clientSecret,
				RedirectURI: redirectURI,
			},
		},
	}

	for _, tc := range []struct {
		Name                 string
		Query                url.Values
		WantReturnedErrMatch func(error) bool
		WantHTTPStatus       int
		CheckResponse        func(*testing.T, SessionManager, *AuthorizationRequest)
	}{
		{
			Name: "Bad client ID should return error directly",
			Query: url.Values{
				"client_id":     []string{"bad-client"},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
			},
			WantReturnedErrMatch: matchHTTPErrStatus(400),
			WantHTTPStatus:       400,
		},
		{
			Name: "Bad redirect URI should return error directly",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{"https://wrong"},
			},
			WantReturnedErrMatch: matchHTTPErrStatus(400),
			WantHTTPStatus:       400,
		},
		{
			Name: "Valid request is parsed correctly",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
			},
			CheckResponse: func(t *testing.T, smgr SessionManager, areq *AuthorizationRequest) {
				if len(areq.ACRValues) > 0 {
					t.Errorf("want 0 acr_values, got: %d", len(areq.ACRValues))
				}

				sess, err := getSession(context.Background(), smgr, areq.SessionID)
				if err != nil {
					t.Errorf("should be able to get the session, got error: %v", err)
				}
				if sess == nil {
					t.Error("session should not be nil")
				}
				if sess.Request == nil {
					t.Error("request in session should not be nil")
				}
			},
		},
		{
			Name: "ACR values correctly parsed",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
				"acr_values":    []string{"mfa smfa"},
			},
			CheckResponse: func(t *testing.T, smgr SessionManager, areq *AuthorizationRequest) {
				if len(areq.ACRValues) != 2 {
					t.Errorf("want 2 acr_values, got: %d", len(areq.ACRValues))
				}
				if diff := cmp.Diff([]string{"mfa", "smfa"}, areq.ACRValues); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			Name: "Implicit flow fails",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"token"},
				"redirect_uri":  []string{redirectURI},
			},
			WantReturnedErrMatch: matchAuthErrCode(authErrorCodeUnsupportedResponseType),
			WantHTTPStatus:       302,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			smgr := newStubSMGR()

			oidc := &OIDC{
				clients: clientSource,
				smgr:    smgr,

				authValidityTime: 1 * time.Minute,
				codeValidityTime: 1 * time.Minute,

				now: time.Now,
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/?"+tc.Query.Encode(), nil)

			resp, err := oidc.StartAuthorization(rec, req)

			if err == nil && tc.WantReturnedErrMatch != nil {
				t.Error("want error retured, got none")
			}
			if err != nil {
				if tc.WantReturnedErrMatch == nil || !tc.WantReturnedErrMatch(err) {
					t.Fatalf("unmatching error returned: %v", err)
				}
			}

			if tc.WantHTTPStatus != 0 {
				if tc.WantHTTPStatus != rec.Code {
					t.Errorf("want HTTP status code %d, got: %d", tc.WantHTTPStatus, rec.Code)
				}
			}

			if tc.CheckResponse != nil {
				tc.CheckResponse(t, smgr, resp)
			}
		})
	}
}

func TestFinishAuthorization(t *testing.T) {
	sessID := mustGenerateID()

	sess := sessionV2{
		ID:       sessID,
		ClientID: "client-id",
		Request: &sessAuthRequest{
			RedirectURI:  "https://redir",
			State:        "state",
			Scopes:       []string{"openid"},
			Nonce:        "nonce",
			ResponseType: authRequestResponseTypeCode,
		},
	}

	for _, tc := range []struct {
		Name                 string
		SessionID            string
		WantReturnedErrMatch func(error) bool
		WantHTTPStatus       int
		Check                func(t *testing.T, smgr SessionManager, rec *httptest.ResponseRecorder)
	}{
		{
			Name:           "Redirects to the correct location",
			SessionID:      sessID,
			WantHTTPStatus: 302,
			Check: func(t *testing.T, smgr SessionManager, rec *httptest.ResponseRecorder) {
				loc := rec.Header().Get("location")

				// strip query to compare base URL
				lnqp, err := url.Parse(loc)
				if err != nil {
					t.Fatal(err)
				}
				lnqp.RawQuery = ""

				if lnqp.String() != sess.Request.RedirectURI {
					t.Errorf("want redir %s, got: %s", sess.Request.RedirectURI, lnqp.String())
				}

				locp, err := url.Parse(loc)
				if err != nil {
					t.Fatal(err)
				}

				// make sure the code resolves to an authCode
				codetok, err := unmarshalToken(locp.Query().Get("code"))
				if err != nil {
					t.Fatal(err)
				}
				gotSess, err := getSession(context.Background(), smgr, codetok.SessionId)
				if err != nil || gotSess == nil {
					t.Errorf("wanted no error fetching session, got: %v", err)
				}

				// make sure the state was passed
				state := locp.Query().Get("state")
				if sess.Request.State != state {
					t.Errorf("want state %s, got: %v", sess.Request.State, state)
				}
			},
		},
		{
			Name:                 "Invalid request ID fails",
			SessionID:            mustGenerateID(),
			WantReturnedErrMatch: matchHTTPErrStatus(403),
			Check: func(t *testing.T, smgr SessionManager, _ *httptest.ResponseRecorder) {
				gotSess := &versionedSession{}
				ok, err := smgr.GetSession(context.Background(), sessID, gotSess)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if ok {
					t.Errorf("want: no session returned, got: %v", gotSess)
				}
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			smgr := newStubSMGR()

			lsess := &sess
			lsess.ID = tc.SessionID

			if err := putSession(ctx, smgr, lsess); err != nil {
				t.Fatal(err)
			}

			oidc := &OIDC{
				smgr: smgr,
				now:  time.Now,

				authValidityTime: 1 * time.Minute,
				codeValidityTime: 1 * time.Minute,
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", nil)

			err := oidc.FinishAuthorization(rec, req, sessID, &Authorization{Scopes: []string{"openid"}})
			checkErrMatcher(t, tc.WantReturnedErrMatch, err)

			if tc.WantHTTPStatus != 0 {
				if tc.WantHTTPStatus != rec.Code {
					t.Errorf("want HTTP status code %d, got: %d", tc.WantHTTPStatus, rec.Code)
				}
			}

			if tc.Check != nil {
				tc.Check(t, smgr, rec)
			}
		})
	}
}

func TestIDTokenPrefill(t *testing.T) {
	now := time.Date(2019, 11, 25, 12, 54, 11, 0, time.UTC)

	nowFn := func() time.Time {
		return now
	}

	for _, tc := range []struct {
		Name string
		TReq TokenRequest
		Want oidc.Claims
	}{
		{
			Name: "Fields filled",
			TReq: TokenRequest{
				ClientID: "client",

				Authorization: Authorization{
					AMR: []string{"amr"},
					ACR: "acr",
				},

				AuthTime: now,
				Nonce:    "nonce",

				now: nowFn,
			},
			Want: oidc.Claims{
				Issuer:   "issuer",
				Subject:  "subject",
				Audience: oidc.Audience{"client"},
				Expiry:   1574686451,
				IssuedAt: 1574686451,
				AuthTime: 1574686451,
				ACR:      "acr",
				Nonce:    "nonce",
				AMR:      []string{"amr"},
				Extra:    map[string]interface{}{},
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tok := tc.TReq.PrefillIDToken("issuer", "subject", now)
			if diff := cmp.Diff(tc.Want, tok, cmpopts.IgnoreUnexported(oidc.Claims{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

type unauthorizedErrImpl struct{ error }

func (u *unauthorizedErrImpl) Unauthorized() bool { return true }

func TestToken(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"

		otherClientID       = "other-client"
		otherClientSecret   = "other-secret"
		otherClientRedirect = "https://other"
	)

	newOIDC := func() *OIDC {
		return &OIDC{
			smgr:   newStubSMGR(),
			signer: testSigner,

			clients: &stubCS{
				validClients: map[string]csClient{
					clientID: csClient{
						Secret:      clientSecret,
						RedirectURI: redirectURI,
					},
					otherClientID: csClient{
						Secret:      otherClientSecret,
						RedirectURI: otherClientRedirect,
					},
				},
			},

			now: time.Now,
		}
	}

	newCodeSess := func(t *testing.T, smgr SessionManager) (usertok string) {
		t.Helper()

		utok, stok, err := newToken(mustGenerateID(), time.Now().Add(1*time.Minute))
		if err != nil {
			t.Fatal(err)
		}

		utokstr, err := marshalToken(utok)
		if err != nil {
			t.Fatal(err)
		}

		sess := &sessionV2{
			ID:            utok.SessionId,
			AuthCode:      stok,
			Authorization: &sessAuthorization{},
			ClientID:      clientID,
			Expiry:        time.Now().Add(1 * time.Minute),
			Request:       &sessAuthRequest{},
		}

		if err := putSession(context.Background(), smgr, sess); err != nil {
			t.Fatal(err)
		}

		return utokstr
	}

	newHandler := func(t *testing.T) func(req *TokenRequest) (*TokenResponse, error) {
		return func(req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{
				AccessTokenValidUntil: time.Now().Add(1 * time.Minute),
			}, nil
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.token(context.Background(), treq, newHandler(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}
	})

	t.Run("Redeeming an already redeemed code should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.token(context.Background(), treq, newHandler(t))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// replay fails
		_, err = o.token(context.Background(), treq, newHandler(t))
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
			t.Errorf("want invalid token grant error, got: %v", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.token(context.Background(), treq, newHandler(t))
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Client secret that differs from the original client should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		treq := &tokenRequest{
			GrantType:   GrantTypeAuthorizationCode,
			Code:        codeToken,
			RedirectURI: redirectURI,
			// This is not the credentials the code should be tracking, but are
			// otherwise valid
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
		}

		_, err := o.token(context.Background(), treq, newHandler(t))
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Response access token validity time honoured", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		ih := newHandler(t)
		h := func(req *TokenRequest) (*TokenResponse, error) {
			r, err := ih(req)
			r.AccessTokenValidUntil = time.Now().Add(5 * time.Minute)
			return r, err
		}

		tresp, err := o.token(context.Background(), treq, h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}

		// compare whole seconds, we calculate this based on a expiresAt - now
		// delta so the function run time is factored in.
		if math.Round(tresp.ExpiresIn.Seconds()) != math.Round((5 * time.Minute).Seconds()) {
			t.Errorf("want token exp %f, got: %f", math.Round((5 * time.Minute).Seconds()), math.Round(tresp.ExpiresIn.Seconds()))
		}
	})

	t.Run("Refresh token happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		ih := newHandler(t)
		h := func(req *TokenRequest) (*TokenResponse, error) {
			r, err := ih(req)
			r.AccessTokenValidUntil = o.now().Add(5 * time.Minute)
			r.RefreshTokenValidUntil = o.now().Add(10 * time.Minute)
			r.IssueRefreshToken = true
			return r, err
		}

		// exchange the code for access/refresh tokens first
		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.token(context.Background(), treq, h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}

		if tresp.RefreshToken == "" {
			t.Error("token request should have returned a refresh token, but got none")
		}

		refreshToken := tresp.RefreshToken

		// keep trying to refresh
		for i := 0; i < 5; i++ {
			treq = &tokenRequest{
				GrantType:    GrantTypeRefreshToken,
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			tresp, err := o.token(context.Background(), treq, h)
			if err != nil {
				t.Fatalf("unexpected error calling token with refresh token: %v", err)
			}

			if tresp.AccessToken == "" {
				t.Error("refresh request should have returned an access token, but got none")
			}

			if tresp.RefreshToken == "" {
				t.Error("refresh request should have returned a refresh token, but got none")
			}

			refreshToken = tresp.RefreshToken
		}

		// march to the future, when we should be expired
		o.now = func() time.Time { return time.Now().Add(1 * time.Hour) }

		treq = &tokenRequest{
			GrantType:    GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.token(context.Background(), treq, h)
		if te, ok := err.(*oauth2.TokenError); !ok || te.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
			t.Errorf("expired session should have given invalid_grant, got: %v", te)
		}
	})

	t.Run("Refresh token with handler errors", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.smgr)

		var returnErr error
		const errDesc = "Refresh unauthorized"

		ih := newHandler(t)
		h := func(req *TokenRequest) (*TokenResponse, error) {
			if returnErr != nil {
				return nil, returnErr
			}
			r, err := ih(req)
			r.AccessTokenValidUntil = o.now().Add(5 * time.Minute)
			r.RefreshTokenValidUntil = o.now().Add(10 * time.Minute)
			r.IssueRefreshToken = true
			return r, err
		}

		// exchange the code for access/refresh tokens first
		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.token(context.Background(), treq, h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// try and refresh, and observe intentional unauth error
		returnErr = &unauthorizedErrImpl{error: errors.New(errDesc)}

		treq = &tokenRequest{
			GrantType:    GrantTypeRefreshToken,
			RefreshToken: tresp.RefreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.token(context.Background(), treq, h)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		terr, ok := err.(*oauth2.TokenError)
		if !ok {
			t.Fatalf("want token error, got: %T", err)
		}
		if terr.ErrorCode != oauth2.TokenErrorCodeInvalidGrant || terr.Description != errDesc {
			t.Fatalf("unexpected code %q (want %q) or description %q (want %q)", terr.ErrorCode, oauth2.TokenErrorCodeInvalidGrant, terr.Description, errDesc)
		}

		// refresh with generic err
		returnErr = errors.New("boomtown")

		treq = &tokenRequest{
			GrantType:    GrantTypeRefreshToken,
			RefreshToken: tresp.RefreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.token(context.Background(), treq, h)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		if _, ok = err.(*httpError); !ok {
			t.Fatalf("want http error, got %T", err)
		}
	})

}

func TestFetchCodeSession(t *testing.T) {
	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and a token
		// request to use.
		Setup func(t *testing.T) (sess *sessionV2, tr *tokenRequest)
		// WantErrMatch signifies that we expect an error. If we don't, it is
		// expected the retrieved session matches the saved session.
		WantErrMatch func(error) bool
		// Cmp compares the sessions. If nil, a simple proto.Equal is performed
		Cmp func(t *testing.T, stored, returned *sessionV2)
	}{
		{
			Name: "Valid session, valid request",
			Setup: func(t *testing.T) (sess *sessionV2, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:       sid,
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sess, tr
			},
			Cmp: func(t *testing.T, stored, returned *sessionV2) {
				if !returned.AuthCodeRedeemed {
					t.Error("auth code should be marked as redeemed")
				}
				if returned.ID != stored.ID {
					t.Error("mismatched session returned")
				}
			},
		},
		{
			Name: "Code that does not correspond to a session",
			Setup: func(t *testing.T) (sess *sessionV2, tr *tokenRequest) {
				badsid := mustGenerateID()
				u, _, err := newToken(badsid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				goodsid := mustGenerateID()
				_, s, err := newToken(goodsid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:       goodsid,
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sess, tr
			},
			WantErrMatch: matchTokenErrCode(oauth2.TokenErrorCodeInvalidGrant),
		},
		{
			Name: "Token with bad data",
			Setup: func(t *testing.T) (sess *sessionV2, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				// tamper with u by changing the actual token data
				u.Token = []byte("willnotmatch")

				sess = &sessionV2{
					ID:       sid,
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sess, tr
			},
			WantErrMatch: matchTokenErrCode(oauth2.TokenErrorCodeInvalidGrant),
		},
		{
			Name: "Code that has expiration time in the past",
			Setup: func(t *testing.T) (sess *sessionV2, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, time.Now().Add(-1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:       sid,
					AuthCode: s,
					Expiry:   time.Now().Add(1 * time.Minute),
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sess, tr
			},
			WantErrMatch: matchTokenErrCode(oauth2.TokenErrorCodeInvalidGrant),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			smgr := newStubSMGR()

			oidc, err := New(&Config{}, smgr, &stubCS{}, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			sess, tr := tc.Setup(t)

			if err := putSession(context.Background(), smgr, sess); err != nil {
				t.Fatalf("error persisting initial session: %v", err)
			}

			got, err := oidc.fetchCodeSession(context.Background(), tr)
			checkErrMatcher(t, tc.WantErrMatch, err)

			if tc.WantErrMatch == nil && tc.Cmp == nil {
				if diff := cmp.Diff(sess, got); diff != "" {
					t.Errorf("returned session doesn't match persisted: %s", diff)
				}
			}

			if tc.Cmp != nil {
				tc.Cmp(t, sess, got)
			}
		})
	}
}

func TestFetchRefreshSession(t *testing.T) {
	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and a token
		// request to use.
		Setup func(t *testing.T) (sess *sessionV2, tr *tokenRequest)
		// WantErrMatch signifies that we expect an error. If we don't, it is
		// expected the retrieved session matches the saved session.
		WantErrMatch func(error) bool
		// Cmp compares the sessions. If nil, a simple proto.Equal is performed
		Cmp func(t *testing.T, stored, returned *sessionV2)
	}{
		{
			Name: "Valid refresh token for a session",
			Setup: func(t *testing.T) (sess *sessionV2, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:           sid,
					RefreshToken: s,
					Expiry:       time.Now().Add(1 * time.Minute),
				}

				tr = &tokenRequest{
					RefreshToken: mustMarshal(u),
				}

				return sess, tr
			},
			Cmp: func(t *testing.T, stored, returned *sessionV2) {
				if returned.RefreshToken != nil {
					t.Error("refresh token should be cleared")
				}
				if returned.ID != stored.ID {
					t.Error("mismatched session returned")
				}
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			smgr := newStubSMGR()

			oidc, err := New(&Config{}, smgr, &stubCS{}, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			sess, tr := tc.Setup(t)

			if err := putSession(context.Background(), smgr, sess); err != nil {
				t.Fatalf("error persisting initial session: %v", err)
			}

			got, err := oidc.fetchRefreshSession(context.Background(), tr)
			checkErrMatcher(t, tc.WantErrMatch, err)

			if tc.WantErrMatch == nil && tc.Cmp == nil {
				if diff := cmp.Diff(sess, got); diff != "" {
					t.Errorf("returned session don't match persisted: %s", cmp.Diff(sess, got))
				}
			}

			if tc.Cmp != nil {
				tc.Cmp(t, sess, got)
			}
		})
	}
}

func TestUserinfo(t *testing.T) {
	echoHandler := func(w io.Writer, uireq *UserinfoRequest) error {
		o := map[string]interface{}{
			"gotsess": uireq.SessionID,
		}

		if err := json.NewEncoder(w).Encode(o); err != nil {
			t.Fatal(err)
		}

		return nil
	}

	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and an access
		// token
		Setup   func(t *testing.T) (sess *sessionV2, accessToken string)
		Handler func(w io.Writer, uireq *UserinfoRequest) error
		// WantErr signifies that we expect an error
		WantErr bool
		// WantJSON is what we want the endpoint to return
		WantJSON map[string]interface{}
	}{
		{
			Name: "Simple output, valid session",
			Setup: func(t *testing.T) (sess *sessionV2, accessToken string) {
				sid := "session-id"
				u, s, err := newToken(sid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:          sid,
					AccessToken: s,
					Expiry:      time.Now().Add(1 * time.Minute),
				}

				return sess, mustMarshal(u)
			},
			Handler: echoHandler,
			WantJSON: map[string]interface{}{
				"gotsess": "session-id",
			},
		},
		{
			Name: "Token for non-existent session",
			Setup: func(t *testing.T) (sess *sessionV2, accessToken string) {
				sid := "session-id"
				u, _, err := newToken(sid, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				return nil, mustMarshal(u)
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "Expired access token",
			Setup: func(t *testing.T) (sess *sessionV2, accessToken string) {
				sid := "session-id"
				u, s, err := newToken(sid, time.Now().Add(-1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &sessionV2{
					ID:          sid,
					AccessToken: s,
					Expiry:      time.Now().Add(1 * time.Minute),
				}

				return sess, mustMarshal(u)
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "No access token",
			Setup: func(t *testing.T) (sess *sessionV2, accessToken string) {
				return nil, ""
			},
			Handler: echoHandler,
			WantErr: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			smgr := newStubSMGR()

			oidc, err := New(&Config{}, smgr, &stubCS{}, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			sess, at := tc.Setup(t)

			if sess != nil {
				if err := putSession(context.Background(), smgr, sess); err != nil {
					t.Fatalf("error persisting initial session: %v", err)
				}
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/userinfo", nil)

			if at != "" {
				req.Header.Set("authorization", "Bearer "+at)
			}

			err = oidc.Userinfo(rec, req, tc.Handler)
			if tc.WantErr && err == nil {
				t.Error("want error, but got none")
			}
			if !tc.WantErr && err != nil {
				t.Errorf("want no error, got: %v", err)
			}
		})
	}
}

func mustMarshal(u *corev1beta1.UserToken) string {
	t, err := marshalToken(u)
	if err != nil {
		panic(err)
	}
	return t
}

func checkErrMatcher(t *testing.T, matcher func(error) bool, err error) {
	t.Helper()
	if err == nil && matcher != nil {
		t.Fatal("want error, got none")
	}
	if err != nil {
		if matcher == nil || !matcher(err) {
			t.Fatalf("unexpected error: %v", err)
		}
		// we have an error and it matched
	}
}

func matchAuthErrCode(code authErrorCode) func(error) bool {
	return func(err error) bool {
		aerr, ok := err.(*authError)
		if !ok {
			return false
		}
		return aerr.Code == code
	}
}

func matchTokenErrCode(code oauth2.TokenErrorCode) func(error) bool {
	return func(err error) bool {
		terr, ok := err.(*oauth2.TokenError)
		if !ok {
			return false
		}
		return terr.ErrorCode == code
	}
}

func matchHTTPErrStatus(code int) func(error) bool {
	return func(err error) bool {
		herr, ok := err.(*httpError)
		if !ok {
			return false
		}
		return herr.Code == code
	}
}

func matchAnyErr() func(error) bool { // nolint:unused,varcheck,deadcode
	return func(err error) bool {
		return err != nil
	}
}
