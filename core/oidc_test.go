package core

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/go-cmp/cmp"
	corestate "github.com/pardot/oidc/proto/deci/corestate/v1beta1"
	"github.com/pardot/oidc/storage"
	"github.com/pardot/oidc/storage/memory"
)

func TestStartAuthorizationClientErrors(t *testing.T) {
	// this is kinda a special case, in that we should _never_ redirect people
	// to a provided redirection endpoint unless it's valid for a valid client
	// ID. Add a special case for this
}

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
		CheckResponse        func(*testing.T, storage.Storage, *AuthorizationResponse)
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
			Name: "Valid request is parsed",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
			},
			CheckResponse: func(t *testing.T, stor storage.Storage, resp *AuthorizationResponse) {
				ar := corestate.AuthRequest{}
				if _, err := stor.Get(context.Background(), authRequestKeyspace, resp.AuthID, &ar); err != nil {
					t.Errorf("should be able to get the auth request, got error: %v", err)
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
			stor := memory.New()

			oidc := &OIDC{
				clients: clientSource,
				storage: stor,

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
				tc.CheckResponse(t, stor, resp)
			}
		})
	}
}

func TestFinishAuthorization(t *testing.T) {
	authReqID := mustGenerateID()

	authReq := &corestate.AuthRequest{
		ClientId:     "client-id",
		RedirectUri:  "https://redir",
		State:        "state",
		Scopes:       []string{"ascope"},
		Nonce:        "nonce",
		ResponseType: corestate.AuthRequest_CODE,
	}

	for _, tc := range []struct {
		Name                 string
		AuthReqID            string
		WantReturnedErrMatch func(error) bool
		WantHTTPStatus       int
		Check                func(t *testing.T, stor storage.Storage, rec *httptest.ResponseRecorder)
	}{
		{
			Name:           "Redirects to the correct location",
			AuthReqID:      authReqID,
			WantHTTPStatus: 302,
			Check: func(t *testing.T, stor storage.Storage, rec *httptest.ResponseRecorder) {
				loc := rec.Header().Get("location")

				// strip query to compare base URL
				lnqp, err := url.Parse(loc)
				if err != nil {
					t.Fatal(err)
				}
				lnqp.RawQuery = ""

				if lnqp.String() != authReq.RedirectUri {
					t.Errorf("want redir %s, got: %s", authReq.RedirectUri, lnqp.String())
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
				sess := corestate.Session{}
				if _, err := stor.Get(context.Background(), authSessionKeyspace, codetok.SessionId, &sess); err != nil {
					t.Errorf("wanted no error fetching auth code, got: %v", err)
				}

				// make sure the state was passed
				state := locp.Query().Get("state")
				if authReq.State != state {
					t.Errorf("want state %s, got: %v", authReq.State, state)
				}
			},
		},
		{
			Name:      "Finishing should remove the authReq",
			AuthReqID: authReqID,
			Check: func(t *testing.T, stor storage.Storage, _ *httptest.ResponseRecorder) {
				_, err := stor.Get(context.Background(), authRequestKeyspace, authReqID, &corestate.AuthRequest{})
				if err == nil || !storage.IsNotFoundErr(err) {
					t.Errorf("want not found for redeemed auth request, got: %v", err)
				}
			},
		},
		{
			Name:      "Invalid request ID fails",
			AuthReqID: mustGenerateID(),
			Check: func(t *testing.T, stor storage.Storage, _ *httptest.ResponseRecorder) {
				_, err := stor.Get(context.Background(), authRequestKeyspace, authReqID, &corestate.AuthRequest{})
				if err == nil || !storage.IsNotFoundErr(err) {
					t.Errorf("want not found for redeemed auth request, got: %v", err)
				}
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			stor := memory.New()

			if _, err := stor.Put(context.Background(), authRequestKeyspace, authReqID, 0, authReq); err != nil {
				t.Fatal(err)
			}

			oidc := &OIDC{
				storage: stor,
				now:     time.Now,

				authValidityTime: 1 * time.Minute,
				codeValidityTime: 1 * time.Minute,
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", nil)

			err := oidc.FinishAuthorization(rec, req, authReqID, []string{"granted"}, &empty.Empty{})
			checkErrMatcher(t, tc.WantReturnedErrMatch, err)

			if tc.WantHTTPStatus != 0 {
				if tc.WantHTTPStatus != rec.Code {
					t.Errorf("want HTTP status code %d, got: %d", tc.WantHTTPStatus, rec.Code)
				}
			}

			if tc.Check != nil {
				tc.Check(t, stor, rec)
			}
		})
	}
}

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
			storage: memory.New(),
			signer:  testSigner,

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

	newCodeSess := func(t *testing.T, stor storage.Storage) (usertok string) {
		t.Helper()

		utok, stok, err := newToken(mustGenerateID(), corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
		if err != nil {
			t.Fatal(err)
		}

		utokstr, err := marshalToken(utok)
		if err != nil {
			t.Fatal(err)
		}

		meta, err := ptypes.MarshalAny(&empty.Empty{})
		if err != nil {
			t.Fatal(err)
		}

		sess := corestate.Session{
			AuthCode: stok,
			Metadata: meta,
			ClientId: clientID,
		}

		if _, err := stor.Put(context.Background(), authSessionKeyspace, utok.SessionId, 0, &sess); err != nil {
			t.Fatal(err)
		}

		return utokstr
	}

	newHandler := func(t *testing.T) func(req *TokenRequest) (*TokenResponse, error) {
		return func(req *TokenRequest) (*TokenResponse, error) {
			meta, err := ptypes.MarshalAny(&empty.Empty{})
			if err != nil {
				t.Fatal(err)
			}

			return &TokenResponse{
				Metadata: meta,

				AccessTokenValidFor: 1 * time.Minute,
			}, nil
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.storage)

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
		codeToken := newCodeSess(t, o.storage)

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
		if err, ok := err.(*tokenError); !ok || err.Code != tokenErrorCodeInvalidGrant {
			t.Errorf("want invalid token grant error, got: %v", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.storage)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.token(context.Background(), treq, newHandler(t))
		if err, ok := err.(*tokenError); !ok || err.Code != tokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Client secret that differs from the original client should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.storage)

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
		if err, ok := err.(*tokenError); !ok || err.Code != tokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Reponse access token validity time honoured", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.storage)

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
			r.AccessTokenValidFor = 5 * time.Minute
			return r, err
		}

		tresp, err := o.token(context.Background(), treq, h)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}

		if tresp.ExpiresIn != 5*time.Minute {
			t.Errorf("want token exp %s, got: %s", (5 * time.Minute).String(), tresp.ExpiresIn.String())
		}
	})
}

func TestFetchCodeSession(t *testing.T) {
	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and a token
		// request to use.
		Setup func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest)
		// WantErrMatch signifies that we expect an error. If we don't, it is
		// expected the retrieved session matches the saved session.
		WantErrMatch func(error) bool
		// Cmp compares the sessions. If nil, a simple proto.Equal is performed
		Cmp func(t *testing.T, stored, returned *corestate.Session)
	}{
		{
			Name: "Valid session, valid request",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &corestate.Session{
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sid, sess, tr
			},
			Cmp: func(t *testing.T, _ *corestate.Session, returned *corestate.Session) {
				if !returned.AuthCode.Expired {
					t.Error("want: code expired, got unexpired")
				}
			},
		},
		{
			Name: "Code that does not correspond to a session",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				badsid := mustGenerateID()
				u, _, err := newToken(badsid, corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				goodsid := mustGenerateID()
				_, s, err := newToken(goodsid, corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &corestate.Session{
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return goodsid, sess, tr
			},
			WantErrMatch: matchTokenErrCode(tokenErrorCodeInvalidGrant),
		},
		{
			Name: "Token with bad data",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				// tamper with u by changing the actual token data
				u.Token = []byte("willnotmatch")

				sess = &corestate.Session{
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sid, sess, tr
			},
			WantErrMatch: matchTokenErrCode(tokenErrorCodeInvalidRequest),
		},
		{
			Name: "After code expiry date",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_AUTH_CODE, time.Now().Add(-1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &corestate.Session{
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sid, sess, tr
			},
			WantErrMatch: matchTokenErrCode(tokenErrorCodeInvalidGrant),
		},
		{
			Name: "Code that has been marked expired",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_AUTH_CODE, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				s.Expired = true

				sess = &corestate.Session{
					AuthCode: s,
				}

				tr = &tokenRequest{
					Code: mustMarshal(u),
				}

				return sid, sess, tr
			},
			WantErrMatch: matchTokenErrCode(tokenErrorCodeInvalidGrant),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			stor := memory.New()

			oidc, err := New(&Config{}, stor, &stubCS{}, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			sessID, sess, tr := tc.Setup(t)

			if _, err := stor.Put(context.Background(), authSessionKeyspace, sessID, 0, sess); err != nil {
				t.Fatalf("error persisting initial session: %v", err)
			}

			_, _, got, err := oidc.fetchCodeSession(context.Background(), tr)
			checkErrMatcher(t, tc.WantErrMatch, err)

			if tc.WantErrMatch == nil && tc.Cmp == nil && !proto.Equal(sess, got) {
				t.Errorf("returned session don't match persisted: %s", cmp.Diff(sess, got))
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
		Setup func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest)
		// WantErrMatch signifies that we expect an error. If we don't, it is
		// expected the retrieved session matches the saved session.
		WantErrMatch func(error) bool
		// Cmp compares the sessions. If nil, a simple proto.Equal is performed
		Cmp func(t *testing.T, stored, returned *corestate.Session)
	}{
		{
			Name: "Valid refresh token for a session",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_REFRESH_TOKEN, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}

				sess = &corestate.Session{
					RefreshTokens: map[string]*corestate.StoredToken{
						u.TokenId: s,
					},
				}

				tr = &tokenRequest{
					RefreshToken: mustMarshal(u),
				}

				return sid, sess, tr
			},
			Cmp: func(t *testing.T, _ *corestate.Session, returned *corestate.Session) {
				var unexpired bool
				for _, v := range returned.RefreshTokens {
					if !v.Expired {
						unexpired = true
					}
				}
				if unexpired {
					t.Error("want: expired refresh tokens, got unexpired")
				}
			},
		},
		{
			Name: "Refresh token that has been redeemed",
			Setup: func(t *testing.T) (sessID string, sess *corestate.Session, tr *tokenRequest) {
				sid := mustGenerateID()
				u, s, err := newToken(sid, corestate.TokenType_REFRESH_TOKEN, time.Now().Add(1*time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				s.Expired = true

				sess = &corestate.Session{
					RefreshTokens: map[string]*corestate.StoredToken{
						u.TokenId: s,
					},
				}

				tr = &tokenRequest{
					RefreshToken: mustMarshal(u),
				}

				return sid, sess, tr
			},
			WantErrMatch: matchTokenErrCode(tokenErrorCodeInvalidGrant),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			stor := memory.New()

			oidc, err := New(&Config{}, stor, &stubCS{}, testSigner)
			if err != nil {
				t.Fatal(err)
			}

			sessID, sess, tr := tc.Setup(t)

			if _, err := stor.Put(context.Background(), authSessionKeyspace, sessID, 0, sess); err != nil {
				t.Fatalf("error persisting initial session: %v", err)
			}

			_, _, got, err := oidc.fetchRefreshSession(context.Background(), tr)
			checkErrMatcher(t, tc.WantErrMatch, err)

			if tc.WantErrMatch == nil && tc.Cmp == nil && !proto.Equal(sess, got) {
				t.Errorf("returned session don't match persisted: %s", cmp.Diff(sess, got))
			}

			if tc.Cmp != nil {
				tc.Cmp(t, sess, got)
			}
		})
	}
}

func mustMarshal(u *corestate.UserToken) string {
	t, err := marshalToken(u)
	if err != nil {
		panic(err)
	}
	return t
}

func checkErrMatcher(t *testing.T, matcher func(error) bool, err error) {
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

func matchTokenErrCode(code tokenErrorCode) func(error) bool {
	return func(err error) bool {
		terr, ok := err.(*tokenError)
		if !ok {
			return false
		}
		return terr.Code == code
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

func matchAnyErr() func(error) bool {
	return func(err error) bool {
		if err != nil {
			return true
		}
		return false
	}
}
