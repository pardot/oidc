package deci

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
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

type App struct {
	logger    logrus.FieldLogger
	sstore    sessions.Store
	storage   storage.Storage
	connector connector.CallbackConnector
	server    *server.Server

	router *mux.Router
}

func NewApp(logger logrus.FieldLogger, connector connector.CallbackConnector, server *server.Server, sstore sessions.Store) (*App, error) {
	a := &App{
		logger:    logger,
		connector: connector,
		server:    server,
		sstore:    sstore,
	}

	a.router = mux.NewRouter()
	a.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Not trying to be RESTful here, as I think an RPC interface will be better at some point anyway
	// See: <https://github.com/heroku/deci/issues/22>
	a.router.HandleFunc("/CreateEnrollOptions", a.handleCreateEnrollOptions).Methods("POST")
	a.router.HandleFunc("/EnrollPublicKey", a.handleEnrollPublicKey).Methods("POST")
	a.router.HandleFunc("/CreateAuthenticateOptions", a.handleCreateAuthenticateOptions).Methods("POST")
	a.router.HandleFunc("/AuthenticatePublicKey", a.handleAuthenticatePublicKey).Methods("POST")

	// OIDC handler. This is called when clients initialize the flow
	a.router.Handle("/auth", server.AuthorizationHandler(http.HandlerFunc(a.handleClientAuthRequest)))

	if err := server.Mount(a.router); err != nil {
		return nil, errors.Wrap(err, "Error mounting OIDC Server")
	}
	a.server = server

	gob.Register(&webauthn.PublicKeyCredentialCreationOptions{})
	gob.Register(&webauthn.PublicKeyCredentialRequestOptions{})

	return a, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/index.html.tmpl", nil)
}

// handleCreateAuthenticateOptions kicks off the 'authentication ceremony'
// (request credentials from an already-enrolled key)
func (a *App) handleCreateAuthenticateOptions(w http.ResponseWriter, r *http.Request) {
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
		UserVerification: webauthn.UserVerificationPreferred, // TODO: Make Required
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(opts); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// handleCreateEnrollOptions kicks off the 'registration ceremony' (enroll a key
// for a logged in user)
func (a *App) handleCreateEnrollOptions(w http.ResponseWriter, r *http.Request) {
	// TODO: Somehow authenticate the user using upstream connector

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

	opts := &webauthn.PublicKeyCredentialCreationOptions{
		RP: webauthn.PublicKeyCredentialRpEntity{
			Name: r.Host,
		},
		User: webauthn.PublicKeyCredentialUserEntity{
			Id:          []byte("TODO"),
			Name:        "TODO",
			DisplayName: "TODO",
		},
		Challenge:        challenge,
		PubKeyCredParams: acceptablePubKeyCredParams,
		AuthenticatorSelection: webauthn.AuthenticatorSelectionCriteria{
			RequireResidentKey: true,
			UserVerification:   webauthn.UserVerificationPreferred, // TODO: Make required
		},
		Attestation: webauthn.AttestationConveyancePreferenceNone,
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(opts); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (a *App) handleEnrollPublicKey(w http.ResponseWriter, r *http.Request) {
	// TODO: Somehow authenticate the user using upstream connector
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	publicKeyCredential := new(webauthn.PublicKeyCredential)
	if err := json.NewDecoder(r.Body).Decode(publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("failed to decode PublicKeyCredential from request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	a.logger.WithField("credentialID", base64.StdEncoding.EncodeToString(publicKeyCredential.Response.AttestationObject.AuthenticatorData.CredentialID)).Info()
	// TODO
	// delete(session.Values, sessionChallgenKey)

	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: Validate challenge and other options

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
}

func (a *App) handleAuthenticatePublicKey(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	publicKeyCredential := new(webauthn.PublicKeyCredential)
	if err := json.NewDecoder(r.Body).Decode(publicKeyCredential); err != nil {
		a.logger.WithError(err).Error("failed to decode PublicKeyCredential from request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	a.logger.Infof("%#v", publicKeyCredential.Response.AuthenticatorData)
	// TODO
	// delete(session.Values, sessionChallgenKey)

	if err := session.Save(r, w); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: Validate challenge and other options

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
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

// handleEnrollRequest kicks off a flow to the upstream server, for the purposes
// of enrolling the user. The "enroll" link should hit this
func (a *App) handleEnrollRequest(w http.ResponseWriter, r *http.Request) {
	sess, _ := a.session(r)
	reqID, ok := sess.Values[sessionAuthRequestIDKey]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	lurl, err := a.connector.LoginURL(connector.Scopes{}, "https://us/callback", reqID.(string))
	if err != nil {
		a.logger.WithError(err).Error("Error creating upstream login URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, lurl, http.StatusTemporaryRedirect)
}

// handleEnrollCallback handles the callback from the upstream provider
func (a *App) handleEnrollCallback(w http.ResponseWriter, r *http.Request) {
	// Fetch the auth request ID from the session
	sess, _ := a.session(r)
	reqID, ok := sess.Values[sessionAuthRequestIDKey]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the connector to handle the callback. This will do the dance, and
	// return the identity
	id, err := a.connector.HandleCallback(connector.Scopes{}, r)
	if err != nil {
		a.logger.WithError(err).Error("Error processing upstream callback response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Persist the webauth information at this step, linking the key to an identity
	// TODO
	// a.storage.CreateAuthKey(keyPubID, id)

	// This is the final step. Fetch the request, then constuct a finalize
	// redirect URL with the identity.
	authReq, err := a.storage.GetAuthRequest(reqID.(string))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redir, err := a.server.FinalizeLogin(id, authReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}

// handleKeyLogin is called when we trigger auth from a known key
func (a *App) handleKeyLogin(w http.ResponseWriter, r *http.Request) {
	// Fetch the auth request ID from the session
	sess, _ := a.session(r)
	reqID, ok := sess.Values[sessionAuthRequestIDKey]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// fetch the refresh token for this key
	// TODO
	// keyData := a.storage.GetAuthKey(keyPubID)
	identity := connector.Identity{UserID: "keydata.Identity"}

	// Trigger a refresh to make sure the user is active, and fetch their latest
	// identity
	// TODO - break glass goes here. What do we do if ID provider down vs. reject?
	rc, ok := a.connector.(connector.RefreshConnector)
	if !ok {
		// TODO - invalidate storage record, this key is unknown
		// TODO - tell key to gtfo?
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newID, err := rc.Refresh(r.Context(), connector.Scopes{}, identity)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Update the key association with the latest ID
	// TODO
	// a.storage.UpdateAuthKey(keyPubID, id)

	// This is the final step. Fetch the request, then constuct a finalize
	// redirect URL with the identity.
	authReq, err := a.storage.GetAuthRequest(reqID.(string))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	redir, err := a.server.FinalizeLogin(newID, authReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}
