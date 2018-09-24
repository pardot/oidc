package deci

type Config struct {
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

	if len(ret.SupportedResponseTypes) == 0 {
		ret.SupportedResponseTypes = []string{"code"}
	}

	return ret
}
