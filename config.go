package deci

type Config struct {
	// RelyingPartyName is a human-friendly name to present to users when they
	// are registering through Webauthn
	RelyingPartyName string

	// Issuer is the OIDC issuer URL
	Issuer string

	// Valid values are "code" to enable the code flow and "token" to enable the implicit
	// flow. If no response types are supplied this value defaults to "code".
	SupportedResponseTypes []string
}

// withDefaults returns the Config, with the default values set if needed
func (c *Config) withDefaults() *Config {
	var ret *Config
	*ret = *c

	if ret.RelyingPartyName == "" {
		ret.RelyingPartyName = "Deci"
	}

	if len(ret.SupportedResponseTypes) == 0 {
		ret.SupportedResponseTypes = []string{"code"}
	}

	return ret
}
