package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// KeySource is used to retrieve the public keys this provider is signing with
type KeySource interface {
	// PublicKeys should return the current signing key set
	PublicKeys(ctx context.Context) (*jose.JSONWebKeySet, error)
}

// KeysHandler is a http.Handler that correctly serves the "keys" endpoint from a keysource
type KeysHandler struct {
	ks       KeySource
	cacheFor time.Duration

	currKeys   *jose.JSONWebKeySet
	currKeysMu sync.Mutex

	lastKeysUpdate time.Time
}

// NewKeysHandler returns a KeysHandler configured to serve the keys froom
// KeySource. It will cache key lookups for the cacheFor duration
func NewKeysHandler(s KeySource, cacheFor time.Duration) *KeysHandler {
	return &KeysHandler{
		ks:       s,
		cacheFor: cacheFor,
	}
}

func (h *KeysHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.currKeysMu.Lock()
	defer h.currKeysMu.Unlock()

	if h.currKeys == nil || time.Now().After(h.lastKeysUpdate) {
		ks, err := h.ks.PublicKeys(req.Context())
		if err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		h.currKeys = ks
		h.lastKeysUpdate = time.Now()
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")

	if err := json.NewEncoder(w).Encode(h.currKeys); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}
