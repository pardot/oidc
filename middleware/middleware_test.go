package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// mockOIDCServer mocks out just enough of an OIDC server for tests. It accepts
// validClientID, validClientSecret and validRedirectURL as parameters, and
// returns an ID token with claims upon success.
type mockOIDCServer struct {
	baseURL           string
	validClientID     string
	validClientSecret string
	validRedirectURL  string
	claims            map[string]interface{}

	key *rsa.PrivateKey

	mux *http.ServeMux
}

func startServer(t *testing.T, handler http.Handler) (baseURL string, cleanup func()) {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	baseURL = fmt.Sprintf("http://localhost:%s", port)
	server := &http.Server{
		Handler: handler,
	}

	go func() { _ = server.Serve(l) }()

	return baseURL, func() {
		_ = server.Shutdown(context.Background())
		_ = l.Close()
	}
}

func startMockOIDCServer(t *testing.T) (server *mockOIDCServer, cleanup func()) {
	t.Helper()

	server = newMockOIDCServer()
	baseURL, cleanup := startServer(t, server)
	server.baseURL = baseURL

	return server, cleanup
}

func newMockOIDCServer() *mockOIDCServer {
	s := &mockOIDCServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/keys", s.handleKeys)
	s.mux = mux

	// Very short key. Used only for testing so generation time is quick.
	s.key = mustGenRSAKey(512)

	return s
}

func (s *mockOIDCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *mockOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "not GET request", http.StatusMethodNotAllowed)
		return
	}

	discovery := struct {
		Issuer                 string   `json:"issuer"`
		AuthorizationEndpoint  string   `json:"authorization_endpoint"`
		TokenEndpoint          string   `json:"token_endpoint"`
		JWKSURI                string   `json:"jwks_uri"`
		ResponseTypesSupported []string `json:"response_types_supported"`
	}{
		Issuer:                 s.baseURL,
		AuthorizationEndpoint:  fmt.Sprintf("%s/auth", s.baseURL),
		TokenEndpoint:          fmt.Sprintf("%s/token", s.baseURL),
		JWKSURI:                fmt.Sprintf("%s/keys", s.baseURL),
		ResponseTypesSupported: []string{"code"},
	}

	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *mockOIDCServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "not GET request", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID != s.validClientID {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI != s.validRedirectURL {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	responseType := r.URL.Query().Get("response_type")
	if responseType != "code" {
		http.Error(w, "invalid response_type", http.StatusBadRequest)
		return
	}

	scope := r.URL.Query().Get("scope")
	if scope != "openid" {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", s.validRedirectURL, url.QueryEscape("valid-code"), url.QueryEscape(state))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "not a POST request", http.StatusMethodNotAllowed)
		return
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	} else if clientID != s.validClientID || clientSecret != s.validClientSecret {
		http.Error(w, "invalid client ID or client secret", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code != "valid-code" {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		// TODO: Support refreshes
		http.Error(w, "invalid grant_type", http.StatusUnauthorized)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != s.validRedirectURL {
		http.Error(w, "invalid redirect_uri", http.StatusUnauthorized)
		return
	}

	jwk := jose.JSONWebKey{
		Key:       s.key,
		Algorithm: "RS256",
		KeyID:     "test",
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	now := time.Now()
	claims := map[string]interface{}{
		"iss": s.baseURL,
		"aud": clientID,
		"exp": now.Add(60 * time.Second).Unix(),
		"iat": now.Unix(),
	}
	for k, v := range s.claims {
		claims[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idToken, err := jws.CompactSerialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
	}{
		AccessToken: "abc123",
		TokenType:   "Bearer",
		IDToken:     idToken,
	}

	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *mockOIDCServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       s.key.Public(),
		Algorithm: "RS256",
		KeyID:     "test",
	}

	if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func TestMiddleware_HappyPath(t *testing.T) {
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf("sub: %s", ClaimFromContext(r.Context(), "sub"))))
	})

	oidcServer, cleanupOIDCServer := startMockOIDCServer(t)
	defer cleanupOIDCServer()

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"

	handler := &Handler{
		Issuer:                   oidcServer.baseURL,
		ClientID:                 oidcServer.validClientID,
		ClientSecret:             oidcServer.validClientSecret,
		SessionAuthenticationKey: []byte("super-secret-key"),
	}

	baseURL, cleanupServer := startServer(t, handler.Wrap(protected))
	defer cleanupServer()

	handler.BaseURL = baseURL

	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", baseURL)
	oidcServer.claims = map[string]interface{}{"sub": "valid-subject"}
	handler.RedirectURL = oidcServer.validRedirectURL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(baseURL)
	if err != nil {
		t.Fatal(err)
	}

	body := checkResponse(t, resp)
	if !bytes.Equal([]byte("sub: valid-subject"), body) {
		t.Fatalf("wanted body %s, got %s", "sub: valid-subject", string(body))
	}
}

func checkResponse(t *testing.T, resp *http.Response) (body []byte) {
	t.Helper()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("bad response: HTTP %d: %s", resp.StatusCode, body)
	}

	return body
}

func mustGenRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}

	return key
}
