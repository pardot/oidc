package deci

import (
	"crypto/rand"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/heroku/deci/internal/storage"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	sessionName          = "deci"
	sessionChallengeKey  = "challenge"
	challengeBytesLength = 32
)

type App struct {
	logger  logrus.FieldLogger
	sstore  sessions.Store
	storage storage.Storage

	router *mux.Router

	now func() time.Time
}

func NewApp(logger logrus.FieldLogger, cfg *Config, sstore sessions.Store) (*App, error) {
	cfg = cfg.withDefaults()

	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing issuer URL %s", cfg.Issuer)
	}

	a := &App{
		logger: logger,
		sstore: sstore,
		now:    time.Now,
	}

	router := mux.NewRouter()
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	router.HandleFunc("/", a.handleIndex)
	router.HandleFunc("/credentials", a.handleCredentialCreate).Methods("POST")

	// OIDC Discovery
	dh, err := discoveryHandler(*issuerURL, cfg.SupportedResponseTypes)
	if err != nil {
		return nil, errors.Wrap(err, "Error building discovery handler")
	}
	router.HandleFunc("/.well-known/openid-configuration", dh)
	router.HandleFunc("/keys", a.handlePublicKeys)
	// OIDC issuance

	a.router = router
	return a, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	a.renderWithDefaultLayout(w, http.StatusOK, "./templates/index.html.tmpl", nil)
}

func (a *App) handleCredentialCreate(w http.ResponseWriter, r *http.Request) {
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
		UserVerification: UserVerificationRequired,
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
	return a.sstore.Get(r, sessionName)
}
