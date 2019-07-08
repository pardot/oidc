package oidcserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2"
)

// LocalConnector is the local passwordDB connector which is an internal
// connector maintained by the server.
const LocalConnector = "local"

// Signer is used for signing the identity tokens
type Signer interface {
	// PublicKeys returns a keyset of all valid signer public keys considered
	// valid for signed tokens
	PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error)
	// SignerAlg returns the algorithm the signer uses
	SignerAlg(ctx context.Context) (jose.SignatureAlgorithm, error)
	// Sign the provided data
	Sign(ctx context.Context, data []byte) (signed []byte, err error)
	// VerifySignature verifies the signature given token against the current signers
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

// ClientSource can be queried to get information about an oauth2 client.
type ClientSource interface {
	// GetClient returns information about the given client ID. It will be
	// called for each lookup.
	GetClient(id string) (*Client, error)
}

// Client represents an OAuth2 client.
//
// For further reading see:
//   * Trusted peers: https://developers.google.com/identity/protocols/CrossClientAuth
//   * Public clients: https://developers.google.com/api-client-library/python/auth/installed-app
type Client struct {
	// Client ID and secret used to identify the client.
	ID     string `json:"id" yaml:"id"`
	Secret string `json:"secret" yaml:"secret"`

	// A registered set of redirect URIs. When redirecting from dex to the client, the URI
	// requested to redirect to MUST match one of these values, unless the client is "public".
	RedirectURIs []string `json:"redirectURIs" yaml:"redirectURIs"`

	// TrustedPeers are a list of peers which can issue tokens on this client's behalf using
	// the dynamic "oauth2:server:client_id:(client_id)" scope. If a peer makes such a request,
	// this client's ID will appear as the ID Token's audience.
	//
	// Clients inherently trust themselves.
	TrustedPeers []string `json:"trustedPeers" yaml:"trustedPeers"`

	// Public clients must use either use a redirectURL 127.0.0.1:X or "urn:ietf:wg:oauth:2.0:oob"
	Public bool `json:"public" yaml:"public"`

	// Name and LogoURL used when displaying this client to the end user.
	Name    string `json:"name" yaml:"name"`
	LogoURL string `json:"logoURL" yaml:"logoURL"`
}

// Config holds the server's configuration options.
//
// Multiple servers using the same storage are expected to be configured identically.
type Config struct {
	Issuer string

	// The backing persistence layer.
	Storage Storage

	// Valid values are "code" to enable the code flow and "token" to enable the implicit
	// flow. If no response types are supplied this value defaults to "code".
	SupportedResponseTypes []string

	// List of allowed origins for CORS requests on discovery, token and keys endpoint.
	// If none are indicated, CORS requests are disabled. Passing in "*" will allow any
	// domain.
	AllowedOrigins []string

	// If enabled, the server won't prompt the user to approve authorization requests.
	// Logging in implies approval.
	SkipApprovalScreen bool

	RotateKeysAfter      time.Duration // Defaults to 6 hours.
	IDTokensValidFor     time.Duration // Defaults to 24 hours
	AuthRequestsValidFor time.Duration // Defaults to 24 hours

	GCFrequency time.Duration // Defaults to 5 minutes

	// If specified, the server will use this function for determining time.
	Now func() time.Time

	Web WebConfig

	Logger logrus.FieldLogger

	PrometheusRegistry *prometheus.Registry
}

// WebConfig holds the server's frontend templates and asset configuration.
//
// These are currently very custom to CoreOS and it's not recommended that
// outside users attempt to customize these.
type WebConfig struct {
	// A filepath to web static.
	//
	// It is expected to contain the following directories:
	//
	//   * static - Static static served at "( issuer URL )/static".
	//   * templates - HTML templates controlled by dex.
	//   * themes/(theme) - Static static served at "( issuer URL )/theme".
	//
	Dir string

	// Defaults to "( issuer URL )/theme/logo.png"
	LogoURL string

	// Defaults to "dex"
	Issuer string

	// Defaults to "coreos"
	Theme string
}

func value(val, defaultValue time.Duration) time.Duration {
	if val == 0 {
		return defaultValue
	}
	return val
}

// Server is the top level object.
type Server struct {
	issuerURL url.URL

	// Map of connector IDs to connectors.
	connectors map[string]Connector

	clients ClientSource

	storage Storage

	mux http.Handler

	templates *templates

	// If enabled, don't prompt user for approval after logging in through connector.
	skipApproval bool

	supportedResponseTypes map[string]bool

	now func() time.Time

	authRequestsValidFor time.Duration
	idTokensValidFor     time.Duration

	signer Signer

	logger logrus.FieldLogger
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c Config) (*Server, error) {
	return newServer(ctx, c)
}

func newServer(ctx context.Context, c Config) (*Server, error) {
	issuerURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("server: can't parse issuer URL")
	}

	if c.Storage == nil {
		return nil, errors.New("server: storage cannot be nil")
	}
	if len(c.SupportedResponseTypes) == 0 {
		c.SupportedResponseTypes = []string{responseTypeCode}
	}

	supported := make(map[string]bool)
	for _, respType := range c.SupportedResponseTypes {
		switch respType {
		case responseTypeCode, responseTypeIDToken, responseTypeToken:
		default:
			return nil, fmt.Errorf("unsupported response_type %q", respType)
		}
		supported[respType] = true
	}

	web := webConfig{
		dir:       c.Web.Dir,
		logoURL:   c.Web.LogoURL,
		issuerURL: c.Issuer,
		issuer:    c.Web.Issuer,
		theme:     c.Web.Theme,
	}

	static, theme, tmpls, err := loadWebConfig(web)
	if err != nil {
		return nil, fmt.Errorf("server: failed to load web static: %v", err)
	}

	now := c.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		issuerURL:              *issuerURL,
		connectors:             make(map[string]Connector),
		storage:                c.Storage,
		supportedResponseTypes: supported,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		authRequestsValidFor:   value(c.AuthRequestsValidFor, 24*time.Hour),
		skipApproval:           c.SkipApprovalScreen,
		now:                    now,
		templates:              tmpls,
		logger:                 c.Logger,
	}

	requestCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Count of all HTTP requests.",
	}, []string{"handler", "code", "method"})

	err = c.PrometheusRegistry.Register(requestCounter)
	if err != nil {
		return nil, fmt.Errorf("server: Failed to register Prometheus HTTP metrics: %v", err)
	}

	instrumentHandlerCounter := func(handlerName string, handler http.Handler) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := httpsnoop.CaptureMetrics(handler, w, r)
			requestCounter.With(prometheus.Labels{"handler": handlerName, "code": strconv.Itoa(m.Code), "method": r.Method}).Inc()
		})
	}

	r := mux.NewRouter()
	handle := func(p string, h http.Handler) {
		r.Handle(path.Join(issuerURL.Path, p), instrumentHandlerCounter(p, h))
	}
	handleFunc := func(p string, h http.HandlerFunc) {
		handle(p, h)
	}
	handlePrefix := func(p string, h http.Handler) {
		prefix := path.Join(issuerURL.Path, p)
		r.PathPrefix(prefix).Handler(http.StripPrefix(prefix, h))
	}
	handleWithCORS := func(p string, h http.HandlerFunc) {
		var handler http.Handler = h
		if len(c.AllowedOrigins) > 0 {
			corsOption := handlers.AllowedOrigins(c.AllowedOrigins)
			handler = handlers.CORS(corsOption)(handler)
		}
		r.Handle(path.Join(issuerURL.Path, p), instrumentHandlerCounter(p, handler))
	}
	r.NotFoundHandler = http.HandlerFunc(http.NotFound)

	discoveryHandler, err := s.discoveryHandler()
	if err != nil {
		return nil, err
	}
	handleWithCORS("/.well-known/openid-configuration", discoveryHandler)

	// TODO(ericchiang): rate limit certain paths based on IP.
	handleWithCORS("/token", s.handleToken)
	handleWithCORS("/keys", s.handlePublicKeys)
	handleWithCORS("/userinfo", s.handleUserInfo)
	handleFunc("/auth", s.handleAuthorization)
	handleFunc("/auth/{connector}", s.handleConnectorLogin)
	r.HandleFunc(path.Join(issuerURL.Path, "/callback"), func(w http.ResponseWriter, r *http.Request) {
		// Strip the X-Remote-* headers to prevent security issues on
		// misconfigured authproxy connector setups.
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-remote-") {
				r.Header.Del(key)
			}
		}
		s.handleConnectorCallback(w, r)
	})
	// For easier connector-specific web server configuration, e.g. for the
	// "authproxy" connector.
	handleFunc("/callback/{connector}", s.handleConnectorCallback)
	handleFunc("/approval", s.handleApproval)
	handle("/healthz", s.newHealthChecker(ctx))
	handlePrefix("/static", static)
	handlePrefix("/theme", theme)
	s.mux = r

	s.startGarbageCollection(ctx, value(c.GCFrequency, 5*time.Minute), now)

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) absPath(pathItems ...string) string {
	paths := make([]string, len(pathItems)+1)
	paths[0] = s.issuerURL.Path
	copy(paths[1:], pathItems)
	return path.Join(paths...)
}

func (s *Server) absURL(pathItems ...string) string {
	u := s.issuerURL
	u.Path = s.absPath(pathItems...)
	return u.String()
}

func newPasswordDB(s Storage) interface {
	Connector
	PasswordConnector
} {
	return passwordDB{s}
}

type passwordDB struct {
	s Storage
}

func (db passwordDB) Login(ctx context.Context, s Scopes, email, password string) (Identity, bool, error) {
	p, err := db.s.GetPassword(email)
	if err != nil {
		if err != ErrNotFound {
			return Identity{}, false, fmt.Errorf("get password: %v", err)
		}
		return Identity{}, false, nil
	}
	// This check prevents dex users from logging in using static passwords
	// configured with hash costs that are too high or low.
	if err := checkCost(p.Hash); err != nil {
		return Identity{}, false, err
	}
	if err := bcrypt.CompareHashAndPassword(p.Hash, []byte(password)); err != nil {
		return Identity{}, false, nil
	}
	return Identity{
		UserID:        p.UserID,
		Username:      p.Username,
		Email:         p.Email,
		EmailVerified: true,
	}, true, nil
}

func (db passwordDB) Refresh(ctx context.Context, s Scopes, identity Identity) (Identity, error) {
	// If the user has been deleted, the refresh token will be rejected.
	p, err := db.s.GetPassword(identity.Email)
	if err != nil {
		if err == ErrNotFound {
			return Identity{}, errors.New("user not found")
		}
		return Identity{}, fmt.Errorf("get password: %v", err)
	}

	// User removed but a new user with the same email exists.
	if p.UserID != identity.UserID {
		return Identity{}, errors.New("user not found")
	}

	// If a user has updated their username, that will be reflected in the
	// refreshed token.
	//
	// No other fields are expected to be refreshable as email is effectively used
	// as an ID and this implementation doesn't deal with groups.
	identity.Username = p.Username

	return identity, nil
}

func (db passwordDB) Prompt() string {
	return "Email Address"
}

func (s *Server) startGarbageCollection(ctx context.Context, frequency time.Duration, now func() time.Time) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(frequency):
				if r, err := s.storage.GarbageCollect(now()); err != nil {
					s.logger.Errorf("garbage collection failed: %v", err)
				} else if r.AuthRequests > 0 || r.AuthCodes > 0 {
					s.logger.Infof("garbage collection run, delete auth requests=%d, auth codes=%d", r.AuthRequests, r.AuthCodes)
				}
			}
		}
	}()
}

const (
	// recCost is the recommended bcrypt cost, which balances hash strength and
	// efficiency.
	recCost = 12

	// upBoundCost is a sane upper bound on bcrypt cost determined by benchmarking:
	// high enough to ensure secure encryption, low enough to not put unnecessary
	// load on a dex server.
	upBoundCost = 16
)

// checkCost returns an error if the hash provided does not meet lower or upper
// bound cost requirements.
func checkCost(hash []byte) error {
	actual, err := bcrypt.Cost(hash)
	if err != nil {
		return fmt.Errorf("parsing bcrypt hash: %v", err)
	}
	if actual < bcrypt.DefaultCost {
		return fmt.Errorf("given hash cost = %d does not meet minimum cost requirement = %d", actual, bcrypt.DefaultCost)
	}
	if actual > upBoundCost {
		return fmt.Errorf("given hash cost = %d is above upper bound cost = %d, recommended cost = %d", actual, upBoundCost, recCost)
	}
	return nil
}
