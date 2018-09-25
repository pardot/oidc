package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/heroku/deci/internal/connector"
	"github.com/heroku/deci/internal/storage"
)

// Config holds the server's configuration options.
//
// Multiple servers using the same storage are expected to be configured identically.
type Config struct {
	Issuer string

	// The backing persistence layer.
	Storage storage.Storage

	// Valid values are "code" to enable the code flow and "token" to enable the implicit
	// flow. If no response types are supplied this value defaults to "code".
	SupportedResponseTypes []string

	// List of allowed origins for CORS requests on discovery, token and keys endpoint.
	// If none are indicated, CORS requests are disabled. Passing in "*" will allow any
	// domain.
	AllowedOrigins []string

	RotateKeysAfter  time.Duration // Defaults to 6 hours.
	IDTokensValidFor time.Duration // Defaults to 24 hours

	GCFrequency time.Duration // Defaults to 5 minutes

	// If specified, the server will use this function for determining time.
	Now func() time.Time

	Logger logrus.FieldLogger

	PrometheusRegistry *prometheus.Registry
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

	// mutex for the connectors map.
	mu sync.Mutex

	storage storage.Storage

	connector connector.Connector

	mux *mux.Router

	supportedResponseTypes map[string]bool

	now func() time.Time

	idTokensValidFor time.Duration

	logger logrus.FieldLogger
}

// NewServer constructs a server from the provided config.
func NewServer(ctx context.Context, c Config) (*Server, error) {
	return newServer(ctx, c, defaultRotationStrategy(
		value(c.RotateKeysAfter, 6*time.Hour),
		value(c.IDTokensValidFor, 24*time.Hour),
	))
}

func newServer(ctx context.Context, c Config, rotationStrategy rotationStrategy) (*Server, error) {
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

	now := c.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		issuerURL:              *issuerURL,
		storage:                newKeyCacher(c.Storage, now),
		supportedResponseTypes: supported,
		idTokensValidFor:       value(c.IDTokensValidFor, 24*time.Hour),
		now:                    now,
		// templates:              tmpls,
		logger: c.Logger,
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
	handleFunc := func(p string, h http.HandlerFunc) {
		r.HandleFunc(path.Join(issuerURL.Path, p), instrumentHandlerCounter(p, h))
	}
	// handlePrefix := func(p string, h http.Handler) {
	// 	prefix := path.Join(issuerURL.Path, p)
	// 	r.PathPrefix(prefix).Handler(http.StripPrefix(prefix, h))
	// }
	handleWithCORS := func(p string, h http.HandlerFunc) {
		var handler http.Handler = h
		if len(c.AllowedOrigins) > 0 {
			corsOption := handlers.AllowedOrigins(c.AllowedOrigins)
			handler = handlers.CORS(corsOption)(handler)
		}
		r.Handle(path.Join(issuerURL.Path, p), handler)
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
	handleFunc("/approval", s.handleApproval)
	handleFunc("/healthz", s.handleHealth)
	s.mux = r

	s.startKeyRotation(ctx, rotationStrategy, now)
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

// newKeyCacher returns a storage which caches keys so long as the next
func newKeyCacher(s storage.Storage, now func() time.Time) storage.Storage {
	if now == nil {
		now = time.Now
	}
	return &keyCacher{Storage: s, now: now}
}

type keyCacher struct {
	storage.Storage

	now  func() time.Time
	keys atomic.Value // Always holds nil or type *storage.Keys.
}

func (k *keyCacher) GetKeys() (storage.Keys, error) {
	keys, ok := k.keys.Load().(*storage.Keys)
	if ok && keys != nil && k.now().Before(keys.NextRotation) {
		return *keys, nil
	}

	storageKeys, err := k.Storage.GetKeys()
	if err != nil {
		return storageKeys, err
	}

	if k.now().Before(storageKeys.NextRotation) {
		k.keys.Store(&storageKeys)
	}
	return storageKeys, nil
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
	return
}
