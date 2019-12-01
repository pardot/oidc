package discovery

import (
	"context"
	"net/http"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

var _ http.Handler = (*Handler)(nil)

// Handler is a http.Handler that can serve the OIDC provider metadata endpoint,
// and optionally keys from a source
//
// It should be mounted at `<issuer>/.well-known/openid-configuration`
type Handler struct {
	md  *ProviderMetadata
	mux *http.ServeMux

	ks             KeySource
	ksCacheFor     time.Duration
	currKeys       []jose.JSONWebKey
	currKeysMu     sync.Mutex
	lastKeysUpdate time.Time
}

// HandlerOpt is an option that can configure
type HandlerOpt func(h *Handler)

// KeySource is used to retrieve the public keys this provider is signing with
type KeySource interface {
	// GetPublicKeys should return the current signign key set
	GetPublicKeys(ctx context.Context) ([]jose.JSONWebKey, error)
}

// WithKeysource adds a keysource to the discovery endpoint. This will enable
// serving of a jwks set on the handler, and configure the metadata to point to
// this. It assumes the metadata contains a valid issuer to build the target
// URL. Keys retrieved will be cached in-memory for the specified duration
func WithKeysource(s KeySource, cacheFor time.Duration) func(h *Handler) {
	return func(h *Handler) {
		h.ks = s
		h.ksCacheFor = cacheFor
		h.md.JWKSURI = h.md.Issuer + "/.well-known/openid-configuration/jwks.json"
		h.mux.HandleFunc("/jwks.json", h.serveKeys)
	}
}

// NewHandler configures and returns a Handler
func NewHandler(metadata *ProviderMetadata, opts ...HandlerOpt) *Handler {
	h := &Handler{
		md:  metadata,
		mux: http.NewServeMux(),
	}
	for _, o := range opts {
		o(h)
	}
	h.mux.HandleFunc("/", h.serveMetadata)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(w, req)
}

func (h *Handler) serveMetadata(w http.ResponseWriter, req *http.Request) {
	if err := json.NewEncoder(w).Encode(h.md); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) serveKeys(w http.ResponseWriter, req *http.Request) {
	h.currKeysMu.Lock()
	defer h.currKeysMu.Unlock()

	if time.Now().After(h.lastKeysUpdate) {
		k, err := h.ks.GetPublicKeys(req.Context())
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		h.currKeys = k
	}

	if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: h.currKeys}); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}
