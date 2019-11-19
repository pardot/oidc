package core

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
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

				authValidityTime:        1 * time.Minute,
				codeValidityTime:        1 * time.Minute,
				accessTokenValidityTime: 1 * time.Minute,

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

func matchAuthErrCode(code authErrorCode) func(error) bool {
	return func(err error) bool {
		aerr, ok := err.(*authError)
		if !ok {
			return false
		}
		return aerr.Code == code
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
				code := locp.Query().Get("code")
				codesp := strings.SplitN(code, ".", 2) // DB ID is the first part, so split
				authCode := corestate.AuthCode{}
				if _, err := stor.Get(context.Background(), authCodeKeyspace, codesp[0], &authCode); err != nil {
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

				authValidityTime:        1 * time.Minute,
				codeValidityTime:        1 * time.Minute,
				accessTokenValidityTime: 1 * time.Minute,

				now: time.Now,
			}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", nil)

			err := oidc.FinishAuthorization(rec, req, authReqID, []string{"granted"}, &empty.Empty{})
			if err == nil && tc.WantReturnedErrMatch != nil {
				t.Fatal("want error, got none")
			}
			if err != nil {
				if tc.WantReturnedErrMatch == nil || !tc.WantReturnedErrMatch(err) {
					t.Fatalf("unexpected error: %v", err)
				}
			}

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

			authValidityTime:        1 * time.Minute,
			codeValidityTime:        1 * time.Minute,
			accessTokenValidityTime: 1 * time.Minute,

			now: time.Now,
		}
	}

	newCode := func(t *testing.T, stor storage.Storage) (tok *token) {
		t.Helper()

		tok, err := newToken()
		if err != nil {
			t.Fatal(err)
		}

		tokPB, err := tok.ToPB()
		if err != nil {
			t.Fatal(err)
		}

		meta, err := ptypes.MarshalAny(&empty.Empty{})
		if err != nil {
			t.Fatal(err)
		}

		code := corestate.AuthCode{
			Code:     tokPB,
			Metadata: meta,
			AuthRequest: &corestate.AuthRequest{
				ClientId: clientID,
			},
		}

		if _, err := stor.Put(context.Background(), authCodeKeyspace, tok.ID(), 0, &code); err != nil {
			t.Fatal(err)
		}

		return tok
	}

	newHandler := func(t *testing.T) func(req *TokenRequest) (*TokenResponse, error) {
		return func(req *TokenRequest) (*TokenResponse, error) {
			meta, err := ptypes.MarshalAny(&empty.Empty{})
			if err != nil {
				t.Fatal(err)
			}

			return &TokenResponse{
				Metadata: meta,
			}, nil
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCode(t, o.storage)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken.String(),
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
		codeToken := newCode(t, o.storage)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken.String(),
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
		if err, ok := err.(*tokenError); !ok || err.Code != tokenErrorCodeInvalidRequest {
			t.Errorf("want invalid token request error, got: %v", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCode(t, o.storage)

		treq := &tokenRequest{
			GrantType:    GrantTypeAuthorizationCode,
			Code:         codeToken.String(),
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
		codeToken := newCode(t, o.storage)

		treq := &tokenRequest{
			GrantType:   GrantTypeAuthorizationCode,
			Code:        codeToken.String(),
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
}
