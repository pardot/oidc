package discovery

import (
	"net/http"

	"gopkg.in/square/go-jose.v2/json"
)

var _ http.Handler = (*ConfigurationHandler)(nil)

// ConfigurationHandler is a http.ConfigurationHandler that can serve the OIDC provider metadata endpoint,
// and optionally keys from a source
//
// It should be mounted at `<issuer>/.well-known/openid-configuration`, and all
// subpaths. This can be achieved with the stdlib mux by using a trailing slash.
// Any prefix should be stripped before calling this ConfigurationHandler
type ConfigurationHandler struct {
	md *ProviderMetadata
}

// ConfigurationHandlerOpt is an option that can configure
type ConfigurationHandlerOpt func(h *ConfigurationHandler)

// WithCoreDefaults is an option that will set the metadata to match the
// capabilities of the `core` OIDC implementation, if they're not otherwise set
func WithCoreDefaults() func(h *ConfigurationHandler) {
	return func(h *ConfigurationHandler) {
		if len(h.md.ResponseTypesSupported) == 0 {
			h.md.ResponseTypesSupported = []string{
				"code",
				"id_token",
				"id_token token",
			}
		}

		if len(h.md.SubjectTypesSupported) == 0 {
			h.md.SubjectTypesSupported = []string{"public"}
		}

		if len(h.md.IDTokenSigningAlgValuesSupported) == 0 {
			h.md.IDTokenSigningAlgValuesSupported = []string{"RS256"}
		}

		if len(h.md.GrantTypesSupported) == 0 {
			h.md.GrantTypesSupported = []string{"authorization_code"}
		}
	}
}

// NewConfigurationHandler configures and returns a ConfigurationHandler.
func NewConfigurationHandler(metadata *ProviderMetadata, opts ...ConfigurationHandlerOpt) (*ConfigurationHandler, error) {
	h := &ConfigurationHandler{
		md: metadata,
	}

	for _, o := range opts {
		o(h)
	}

	if err := h.md.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

func (h *ConfigurationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(h.md); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}
