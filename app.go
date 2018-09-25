package deci

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/heroku/deci/internal/connector"
	"github.com/heroku/deci/internal/server"
	"github.com/heroku/deci/internal/storage"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	sessionName          = "deci"
	sessionChallengeKey  = "challenge"
	challengeBytesLength = 32
)

var (
	acceptablePubKeyCredParams = []PublicKeyCredentialParameters{
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmES256,
		},
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmES384,
		},
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmES512,
		},
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmPS256,
		},
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmPS384,
		},
		{
			Type: PublicKeyCredentialTypePublicKey,
			Alg:  COSEAlgorithmPS512,
		},
	}
)

type App struct {
	logger           logrus.FieldLogger
	sstore           sessions.Store
	storage          storage.Storage
	connector        connector.CallbackConnector
	dserver          *server.Server
	relyingPartyName string

	router *mux.Router
}

func NewApp(logger logrus.FieldLogger, cfg *Config, dcfg *server.Config, sstore sessions.Store) (*App, error) {
	a := &App{
		logger:           logger,
		sstore:           sstore,
		relyingPartyName: cfg.RelyingPartyName,
	}

	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	router.HandleFunc("/", a.handleIndex)
	router.HandleFunc("/credentialrequests", a.handleCreateCredentialRequest).Methods("POST")
	router.HandleFunc("/credentials", a.handleCreateCredential).Methods("POST")

	dserver, err := server.NewServer(context.Background(), dcfg)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating OIDC server")
	}

	if err := dserver.Mount(router); err != nil {
		return nil, errors.Wrap(err, "Error mounting OIDC Server")
	}

	a.router = router
	a.dserver = dserver
	return a, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/index.html.tmpl", nil)
}

// handleCreateCredentialRequest kicks off the 'authentication ceremony'
// (request credentials from an already-enrolled key)
func (a *App) handleCreateCredentialRequest(w http.ResponseWriter, r *http.Request) {
	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// No user lookup is done here to avoid username enumeration:
	// https://w3c.github.io/webauthn/#sctn-username-enumeration
	challenge := make([]byte, challengeBytesLength)
	if _, err := rand.Read(challenge); err != nil {
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

	body := &PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		UserVerification: UserVerificationPreferred, // TODO: Make Required
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// handleCreateCredential kicks off the 'registration ceremony' (enroll a key
// for a logged in user)
func (a *App) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	// TODO: Somehow authenticate the user using upstream connector

	session, err := a.session(r)
	if err != nil {
		a.logger.WithError(err).Error()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// No user lookup is done here to avoid username enumeration:
	// https://w3c.github.io/webauthn/#sctn-username-enumeration
	challenge := make([]byte, challengeBytesLength)
	if _, err := rand.Read(challenge); err != nil {
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

	body := &PublicKeyCredentialCreationOptions{
		RP: PublicKeyCredentialRpEntity{
			Name: a.relyingPartyName,
		},
		User: PublicKeyCredentialUserEntity{
			Id:          []byte("TODO"),
			Name:        "TODO",
			DisplayName: "TODO",
		},
		Challenge:        challenge,
		PubKeyCredParams: acceptablePubKeyCredParams,
		AuthenticatorSelection: AuthenticatorSelectionCriteria{
			RequireResidentKey: true,
			UserVerification:   UserVerificationPreferred, // TODO: Make required
		},
		Attestation: AttestationConveyancePreferenceNone, // TODO: Is this right?
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
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

// genHandleClientAuthRequest returns a HTTP handler that is mounted inside the
// OIDC server. This is called when a client initalizes the auth flow
func (a *App) genHandleClientAuthRequest(s *server.Server, st storage.Storage) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// this has to be threaded through all the requests to correctly
		// generate the final step. Get it, and stuff it in the session
		reqID, ok := server.AuthRequestID(r.Context())
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sess, _ := a.session(r)
		sess.Values["auth-request-id"] = reqID
		if err := sess.Save(r, w); err != nil {
			a.logger.WithError(err).Warn("Error saving session")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Render the "index" page here. This should prompt the user to verify
		// themselves using webauthn, or ask if they want to enroll
	})
}

// handleEnrollRequest kicks off a flow to the upstream server, for the purposes
// of enrolling the user. The "enroll" link should hit this
func (a *App) handleEnrollRequest(w http.ResponseWriter, r *http.Request) {
	sess, _ := a.session(r)
	reqID, ok := sess.Values["auth-request-id"]
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
	reqID, ok := sess.Values["auth-request-id"]
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
	redir, err := a.dserver.FinalizeLogin(id, authReq)
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
	reqID, ok := sess.Values["auth-request-id"]
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
	redir, err := a.dserver.FinalizeLogin(newID, authReq)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redir, http.StatusTemporaryRedirect)
}
