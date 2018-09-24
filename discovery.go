package deci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	jose "gopkg.in/square/go-jose.v2"
)

type discovery struct {
	Issuer        string   `json:"issuer"`
	Auth          string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
	Scopes        []string `json:"scopes_supported"`
	AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	Claims        []string `json:"claims_supported"`
}

func discoveryHandler(iss url.URL, supportedResponseTypes []string) (http.HandlerFunc, error) {
	d := discovery{
		Issuer:      iss.String(),
		Auth:        absURL(iss, "/auth"),
		Token:       absURL(iss, "/token"),
		Keys:        absURL(iss, "/keys"),
		Subjects:    []string{"public"},
		IDTokenAlgs: []string{string(jose.RS256)},
		Scopes:      []string{"openid", "email", "groups", "profile", "offline_access"},
		AuthMethods: []string{"client_secret_basic"},
		Claims: []string{
			"aud", "email", "email_verified", "exp",
			"iat", "iss", "locale", "name", "sub",
		},
	}

	sort.Strings(supportedResponseTypes)

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discovery data: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}), nil
}

func (a *App) handlePublicKeys(w http.ResponseWriter, r *http.Request) {
	// TODO(ericchiang): Cache this.
	keys, err := a.storage.GetKeys()
	if err != nil {
		a.logger.Errorf("failed to get keys: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if keys.SigningKeyPub == nil {
		a.logger.Errorf("No public keys found.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keys.VerificationKeys)+1),
	}
	jwks.Keys[0] = *keys.SigningKeyPub
	for i, verificationKey := range keys.VerificationKeys {
		jwks.Keys[i+1] = *verificationKey.PublicKey
	}

	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		a.logger.Errorf("failed to marshal discovery data: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	maxAge := keys.NextRotation.Sub(a.now())
	if maxAge < (time.Minute * 2) {
		maxAge = time.Minute * 2
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d, must-revalidate", int(maxAge.Seconds())))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
