package deci

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/heroku/deci/internal/connector"
	"github.com/heroku/deci/internal/server"
	"github.com/heroku/deci/internal/storage"
	"github.com/heroku/deci/internal/webauthn"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	sessionName             = "deci"
	sessionChallengeKey     = "challenge"
	sessionAuthRequestIDKey = "auth-req-id"
	sessionApprovalURLKey   = "approval-url"

	pathStartEnrollment             = "/StartEnrollment"
	pathCreateEnrollmentOptions     = "/CreateEnrollmentOptions"
	pathEnrollPublicKey             = "/EnrollPublicKey"
	pathCreateAuthenticationOptions = "/CreateAuthenticationOptions"
	pathAuthenticatePublicKey       = "/AuthenticatePublicKey"
)

var (
	acceptablePubKeyCredParams = []webauthn.PublicKeyCredentialParameters{
		{
			Type:      webauthn.PublicKeyCredentialTypePublicKey,
			Algorithm: webauthn.COSEAlgorithmES256,
		},
		{
			Type:      webauthn.PublicKeyCredentialTypePublicKey,
			Algorithm: webauthn.COSEAlgorithmES384,
		},
		{
			Type:      webauthn.PublicKeyCredentialTypePublicKey,
			Algorithm: webauthn.COSEAlgorithmES512,
		},
	}
)

type redirectResponse struct {
	RedirectURL string `json:"redirectURL"`
}

type App struct {
	logger    logrus.FieldLogger
	sstore    sessions.Store
	storage   storage.Storage
	connector connector.CallbackConnector
	server    *server.Server

	router *mux.Router
}

func NewApp(logger logrus.FieldLogger, connector connector.CallbackConnector, storage storage.Storage, server *server.Server, sstore sessions.Store) (*App, error) {
	a := &App{
		logger:    logger,
		connector: connector,
		storage:   storage,
		server:    server,
		sstore:    sstore,
	}

	a.router = mux.NewRouter()
	a.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Not trying to be RESTful here, as I think an RPC interface will be better at some point anyway
	// See: <https://github.com/heroku/deci/issues/22>
	a.router.HandleFunc(pathStartEnrollment, a.handleStartEnrollment).Methods("GET")
	a.router.HandleFunc(pathCreateEnrollmentOptions, a.handleCreateEnrollmentOptions).Methods("POST")
	a.router.HandleFunc(pathEnrollPublicKey, a.handleEnrollPublicKey).Methods("POST")
	a.router.HandleFunc(pathCreateAuthenticationOptions, a.handleCreateAuthenticationOptions).Methods("POST")
	a.router.HandleFunc(pathAuthenticatePublicKey, a.handleAuthenticatePublicKey).Methods("POST")

	// OIDC handler. This is called when clients initialize the flow
	a.router.Handle("/auth", server.AuthorizationHandler(http.HandlerFunc(a.handleClientAuthRequest)))
	// OAuth callback handler. The client is redirected here after authenticating to the upstream connector
	a.router.Handle("/callback", server.CallbackHandler(http.HandlerFunc(a.handleStartEnrollmentCallback)))

	if err := server.Mount(a.router); err != nil {
		return nil, errors.Wrap(err, "Error mounting OIDC Server")
	}
	a.server = server

	return a, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/index.html.tmpl", nil)
}

// handleCreateAuthenticationOptions kicks off the 'authentication ceremony'
// (request credentials from an already-enrolled key)
func (a *App) handleCreateAuthenticationOptions(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	challenge, err := webauthn.NewChallenge()
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.Values[sessionChallengeKey] = challenge

	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := &webauthn.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		UserVerification: webauthn.UserVerificationRequired,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(opts); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// handleCreateEnrollmentOptions kicks off the 'registration ceremony' (enroll
// a key for a logged in user)
func (a *App) handleCreateEnrollmentOptions(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqID, ok := session.Values[sessionAuthRequestIDKey].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq, err := a.storage.GetAuthRequest(reqID)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	challenge, err := webauthn.NewChallenge()
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session.Values[sessionChallengeKey] = challenge

	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := &webauthn.PublicKeyCredentialCreationOptions{
		RP: webauthn.PublicKeyCredentialRpEntity{
			Name: r.Host,
		},
		User: webauthn.PublicKeyCredentialUserEntity{
			Id:          []byte(authReq.Claims.UserID), // TODO: This should not be personally identifiable, per the spec. We could hash+salt this?
			Name:        authReq.Claims.Email,
			DisplayName: authReq.Claims.Username,
		},
		Challenge:        challenge,
		PubKeyCredParams: acceptablePubKeyCredParams,
		AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
			RequireResidentKey: true,
			UserVerification:   webauthn.UserVerificationRequired,
		},
		Attestation: webauthn.AttestationConveyancePreferenceNone,
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(opts); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (a *App) handleEnrollPublicKey(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqID, ok := session.Values[sessionAuthRequestIDKey].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq, err := a.storage.GetAuthRequest(reqID)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else if !authReq.LoggedIn {
		a.logger.Warn("attempted to enroll using non-logged-in auth request")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	identity := authReq.Claims.Identity(authReq.ConnectorData)

	challenge, ok := session.Values[sessionChallengeKey].([]byte)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	publicKeyCredential := new(webauthn.PublicKeyCredential)
	if err := json.NewDecoder(r.Body).Decode(publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("failed to decode PublicKeyCredential from request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := a.validateEnrollment(challenge, publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("enrollment validation failed")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = a.storage.UpsertWebauthAssociation(
		publicKeyCredential.Response.AttestationObject.AuthenticatorData.CredentialID,
		int(publicKeyCredential.Response.AttestationObject.AuthenticatorData.Counter),
		*publicKeyCredential.Response.AttestationObject.AuthenticatorData.CredentialPublicKey,
		identity,
	)
	if err != nil {
		a.logger.WithError(err).Error("upserting webauthn association failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	delete(session.Values, sessionChallengeKey)
	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := &redirectResponse{
		RedirectURL: a.server.ApprovalURL(reqID),
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (a *App) handleAuthenticatePublicKey(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqID, ok := session.Values[sessionAuthRequestIDKey].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq, err := a.storage.GetAuthRequest(reqID)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	challenge, ok := session.Values[sessionChallengeKey].([]byte)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	publicKeyCredential := new(webauthn.PublicKeyCredential)
	if err := json.NewDecoder(r.Body).Decode(publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("failed to decode PublicKeyCredential from request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	publicKey, identity, err := a.storage.GetWebauthAssociation(publicKeyCredential.RawID)
	if err != nil {
		a.logger.WithError(err).Error("failed to fetch webauthn association")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := a.validateAuthentication(challenge, &publicKey, nil, publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("authentication failed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Trigger a refresh to make sure the user is active, and fetch their latest
	// identity
	// TODO - break glass goes here. What do we do if ID provider down vs. reject?
	rc, ok := a.connector.(connector.RefreshConnector)
	if !ok {
		// TODO - invalidate storage record, this key is unknown
		// TODO - tell key to gtfo?
		a.logger.Error("connector is not a refresh connector")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	scopes := server.ParseScopes(authReq.Scopes)
	scopes.OfflineAccess = true

	newIdentity, err := rc.Refresh(r.Context(), scopes, identity)
	if err != nil {
		a.logger.WithError(err).Error("failed to issue new identity")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = a.storage.UpsertWebauthAssociation(
		publicKeyCredential.RawID,
		int(publicKeyCredential.Response.AuthenticatorData.Counter),
		publicKey,
		newIdentity,
	)
	if err != nil {
		a.logger.WithError(err).Error("upserting webauthn association failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	delete(session.Values, sessionChallengeKey)
	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	redirectURL, err := a.server.FinalizeLogin(newIdentity, authReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := &redirectResponse{
		RedirectURL: redirectURL,
	}

	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (a *App) renderWithDefaultLayout(w http.ResponseWriter, code int, filename string, data interface{}) {
	t, err := template.ParseFiles("./templates/layouts/default.html.tmpl", filename)
	if err != nil {
		a.logger.WithError(err).Error()
		http.Error(w, "failed to parse templates", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	if err := t.Execute(w, data); err != nil {
		a.logger.WithError(err).Error()
		http.Error(w, "failed to execute template", http.StatusInternalServerError)
		return
	}
}

func (a *App) session(r *http.Request) (*sessions.Session, error) {
	session, err := a.sstore.Get(r, sessionName)
	if err != nil {
		if session != nil && session.IsNew {
			// If the cookie was tampered with or is otherwise invalid, Get() will return
			// both a new (empty) session _and_ an error. We're OK with just using the
			// empty session in that case. This mostly happens locally when developers
			// may regenerate the cookie secret/encryption key often.
			a.logger.WithError(err).Info("Session decoding failed, a new empty session will be used")
			err = nil
		}
	}
	return session, err
}

// handleClientAuthRequest returns a HTTP handler that is mounted inside the
// OIDC server. This is called when a client initalizes the auth flow
func (a *App) handleClientAuthRequest(w http.ResponseWriter, r *http.Request) {
	// this has to be threaded through all the requests to correctly
	// generate the final step. Get it, and stuff it in the session
	reqID, ok := server.AuthRequestID(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session.Values[sessionAuthRequestIDKey] = reqID
	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/index.html.tmpl", nil)
}

// handleStartEnrollment kicks off a flow to the upstream server. If the user
// authenticates successfully, they are given the option to enroll a public
// key.
func (a *App) handleStartEnrollment(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqID, ok := session.Values[sessionAuthRequestIDKey].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq, err := a.storage.GetAuthRequest(reqID)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	scopes := server.ParseScopes(authReq.Scopes)
	scopes.OfflineAccess = true

	lurl, err := a.connector.LoginURL(scopes, a.server.CallbackURL(), reqID)
	if err != nil {
		a.logger.WithError(err).Error("error creating upstream login URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, lurl, http.StatusSeeOther)
}

// handleStart handles the callback from the upstream provider
func (a *App) handleStartEnrollmentCallback(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqID, ok := session.Values[sessionAuthRequestIDKey].(string)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	identity, ok := server.Identity(r.Context())
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq, err := a.storage.GetAuthRequest(reqID)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = a.server.FinalizeLogin(identity, authReq)
	if err != nil {
		a.logger.WithError(err).Error("error finalizing login")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/enrollment.html.tmpl", nil)
}

// validateEnrollment validates that an enrollment request is valid. It is up
// to the calling code to authenticate the user by some other means initially,
// and to save the resulting credential in a data store.
//
// See: <https://w3c.github.io/webauthn/#registering-a-new-credential>
func (a *App) validateEnrollment(challenge []byte, publicKeyCredential *webauthn.PublicKeyCredential) error {
	if len(publicKeyCredential.Response.ClientDataJSON) == 0 {
		return errors.New("missing clientDataJSON")
	} else if publicKeyCredential.Response.AttestationObject == nil {
		return errors.New("missing attestation object")
	} else if len(publicKeyCredential.Response.AttestationObject.AuthenticatorData.CredentialID) == 0 {
		return errors.New("missing credential ID")
	} else if publicKeyCredential.Response.AttestationObject.AuthenticatorData.CredentialPublicKey == nil {
		return errors.New("missing public key")
	}

	// 1. Let JSONtext be the result of running UTF-8 decode on the value of
	// response.clientDataJSON.
	clientDataJSON := publicKeyCredential.Response.ClientDataJSON

	// 2. Let C, the client data claimed as collected during the credential
	// creation, be the result of running an implementation-specific JSON parser
	// on JSONtext.
	var clientData webauthn.CollectedClientData
	if err := json.NewDecoder(bytes.NewReader(clientDataJSON)).Decode(&clientData); err != nil {
		return errors.Wrap(err, "failed to decode clientDataJSON")
	}

	// 3. Verify that the value of C.type is webauthn.create.
	if clientData.Type != webauthn.ClientDataTypeCreate {
		return fmt.Errorf("clientData.Type was not %s", webauthn.ClientDataTypeCreate)
	}

	// 4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
	if len(clientData.Challenge) == 0 || !bytes.Equal(clientData.Challenge, challenge) {
		return errors.New("challenge did not match")
	}

	// 5. Verify that the value of C.origin matches the Relying Party's origin.
	// TODO: We have let the browser auto-generate rpID now. Is it necessary to
	// validate it server-side?

	// 6. Verify that the value of C.tokenBinding.status matches the state of Token
	// Binding for the TLS connection over which the assertion was obtained. If
	// Token Binding was used on that TLS connection, also verify that
	// C.tokenBinding.id matches the base64url encoding of the Token Binding ID
	// for the connection.
	// NOTE: We are not currently requesting token binding

	// 7. Compute the hash of response.clientDataJSON using SHA-256.
	_ = sha256.Sum256(clientDataJSON)

	// 8. Perform CBOR decoding on the attestationObject field of the
	// AuthenticatorAttestationResponse structure to obtain the attestation
	// statement format fmt, the authenticator data authData, and the attestation
	// statement attStmt.
	// NOTE: We are not currently requesting attestation

	// 9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of
	// the RP ID expected by the Relying Party.
	// TODO: We have let the browser auto-generate rpID now. Is it necessary to
	// validate it server-side?

	// 10. Verify that the User Present bit of the flags in authData is set.
	if !publicKeyCredential.Response.AttestationObject.AuthenticatorData.IsUserPresent() {
		return errors.New("user not present")
	}

	// 11. If user verification is required for this registration, verify that
	// the User Verified bit of the flags in authData is set.
	if !publicKeyCredential.Response.AttestationObject.AuthenticatorData.IsUserVerified() {
		return errors.New("user not verified")
	}

	// 12. Verify that the values of the client extension outputs in
	// clientExtensionResults and the authenticator extension outputs in the
	// extensions in authData are as expected
	// NOTE: We currently do not request client extensions

	// 13. Determine the attestation statement format by performing a USASCII
	// case-sensitive match on fmt against the set of supported WebAuthn
	// Attestation Statement Format Identifier values.
	// 14. Verify that attStmt is a correct attestation statement, conveying a
	// valid attestation signature, by using the attestation statement format
	// fmt’s verification procedure given attStmt, authData and the hash of the
	// serialized client data computed in step 7.
	// NOTE: We are not requesting attestation at this time

	// 15. If validation is successful, obtain a list of acceptable trust anchors
	// (attestation root certificates or ECDAA-Issuer public keys) for that
	// attestation type and attestation statement format fmt, from a trusted
	// source or from policy.
	// 16. Assess the attestation trustworthiness using the outputs of the
	// verification procedure in step 14
	// NOTE: We are not requesting attestation at this time

	// 17. Check that the credentialId is not yet registered to any other user.
	// If registration is requested for a credential that is already registered
	// to a different user, the Relying Party SHOULD fail this registration
	// ceremony, or it MAY decide to accept the registration, e.g. while deleting
	// the older registration.
	// NOTE: It is the caller's responsibility to figure out what to do in this
	// case

	// 18. If the attestation statement attStmt verified successfully and is
	// found to be trustworthy, then register the new credential with the account
	// that was denoted in the options.user passed to create(), by associating it
	// with the credentialId and credentialPublicKey in the
	// attestedCredentialData in authData, as appropriate for the Relying Party's
	// system.
	return nil
}

// validateAuthentication validates that an authentication request is valid.
// The challenge and publicKey should have been loaded from a data store, saved
// when the user previously enrolled the key.
//
// See: <https://w3c.github.io/webauthn/#verifying-assertion>
func (a *App) validateAuthentication(challenge []byte, publicKey *webauthn.COSEPublicKey, userHandle []byte, publicKeyCredential *webauthn.PublicKeyCredential) error {
	if len(publicKeyCredential.Response.ClientDataJSON) == 0 {
		return errors.New("missing clientDataJSON")
	} else if publicKeyCredential.Response.AuthenticatorData == nil {
		return errors.New("missing authenticator data")
	} else if len(publicKeyCredential.Response.Signature) == 0 {
		return errors.New("missing signature")
	}

	// 1. If the allowCredentials option was given when this authentication
	// ceremony was initiated, verify that credential.id identifies one of the
	// public key credentials that were listed in allowCredentials.
	// NOTE: The publicKey has already been loaded by the caller

	// 2. If credential.response.userHandle is present, verify that the user
	// identified by this value is the owner of the public key credential
	// identified by credential.id.
	if len(publicKeyCredential.Response.UserHandle) > 0 && len(userHandle) > 0 && !bytes.Equal(publicKeyCredential.Response.UserHandle, userHandle) {
		return errors.New("user handle does not match")
	}

	// 3. Using credential's id attribute (or the corresponding rawId, if
	// base64url encoding is inappropriate for your use case), look up the
	// corresponding credential public key.
	// NOTE: The publicKey has already been loaded by the caller

	// 4. Let cData, authData and sig denote the value of credential’s response's
	// clientDataJSON, authenticatorData, and signature respectively.
	// 5. Let JSONtext be the result of running UTF-8 decode on the value of
	// cData.
	clientDataJSON := publicKeyCredential.Response.ClientDataJSON

	// 6. Let C, the client data claimed as used for the signature, be the result
	// of running an implementation-specific JSON parser on JSONtext.
	var clientData webauthn.CollectedClientData
	if err := json.NewDecoder(bytes.NewReader(clientDataJSON)).Decode(&clientData); err != nil {
		return errors.Wrap(err, "failed to decode clientDataJSON")
	}

	// 7. Verify that the value of C.type is the string webauthn.get.
	if clientData.Type != webauthn.ClientDataTypeGet {
		return fmt.Errorf("clientData.Type was not %s", webauthn.ClientDataTypeGet)
	}

	// 8. Verify that the value of C.challenge matches the challenge that was
	// sent to the authenticator in the PublicKeyCredentialRequestOptions passed
	// to the get() call.
	if len(clientData.Challenge) == 0 || !bytes.Equal(clientData.Challenge, challenge) {
		return errors.New("challenge did not match")
	}

	// 9. Verify that the value of C.origin matches the Relying Party's origin.
	// TODO: We have let the browser auto-generate rpID now. Is it necessary to
	// validate it server-side?

	// 10. Verify that the value of C.tokenBinding.status matches the state of
	// Token Binding for the TLS connection over which the attestation was
	// obtained. If Token Binding was used on that TLS connection, also verify
	// that C.tokenBinding.id matches the base64url encoding of the Token Binding
	// ID for the connection.
	// NOTE: We are not currently requesting token binding

	// 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
	// expected by the Relying Party.
	// TODO: We have let the browser auto-generate rpID now. Is it necessary to
	// validate it server-side?

	// 12. Verify that the User Present bit of the flags in authData is set.
	if !publicKeyCredential.Response.AuthenticatorData.IsUserPresent() {
		return errors.New("user not present")
	}

	// 13. If user verification is required for this assertion, verify that the
	// User Verified bit of the flags in authData is set.
	if !publicKeyCredential.Response.AuthenticatorData.IsUserVerified() {
		return errors.New("user not verified")
	}

	// 14. Verify that the values of the client extension outputs in
	// clientExtensionResults and the authenticator extension outputs in the
	// extensions in authData are as expected
	// NOTE: We currently do not request client extensions

	// 15. Let hash be the result of computing a hash over the cData using SHA-256.
	hash := sha256.Sum256(publicKeyCredential.Response.ClientDataJSON)

	// 16. Using the credential public key looked up in step 3, verify that sig
	// is a valid signature over the binary concatenation of authData and hash.
	authData := publicKeyCredential.Response.AuthenticatorData.Raw()
	if authData == nil {
		return errors.New("missing raw auth data")
	}

	// TODO: Support RSA keys if we care?
	key, err := publicKey.ECDSAKey()
	if err != nil {
		return err
	}

	var sigValue webauthn.ECDSASignatureValue
	if _, err := asn1.Unmarshal(publicKeyCredential.Response.Signature, &sigValue); err != nil {
		return errors.Wrap(err, "failed to decode signature value")
	}

	signedData := make([]byte, len(authData)+len(hash))
	copy(signedData, authData)
	copy(signedData[len(authData):], hash[:])
	signedHash := sha256.Sum256(signedData)

	if !ecdsa.Verify(key, signedHash[:], sigValue.R, sigValue.S) {
		return errors.New("invalid signature")
	}

	// If the signature counter value authData.signCount is nonzero or the value
	// stored in conjunction with credential’s id attribute is nonzero, then run
	// the following sub-step:
	// NOTE: It is the caller's responsibility to figure out what to do in this
	// case
	return nil
}
