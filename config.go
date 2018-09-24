package deci

type Config struct {
	// RelyingPartyName is a human-friendly name to present to users when they
	// are registering through Webauthn
	RelyingPartyName string
}

// withDefaults returns the Config, with the default values set if needed
func (c *Config) withDefaults() *Config {
	var ret *Config
	*ret = *c

	if ret.RelyingPartyName == "" {
		ret.RelyingPartyName = "Deci"
	}

	return ret
}
