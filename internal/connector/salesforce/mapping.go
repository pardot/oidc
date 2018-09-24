package salesforce

import (
	"io/ioutil"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
)

// LoadMappings returns a mapping of Subject -> group memberships
func LoadMappings(path string) (map[string][]string, error) {
	var m map[string][]string

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return m, errors.Wrapf(err, "Error reading %s", path)
	}

	if err := yaml.Unmarshal(b, &m); err != nil {
		return m, err
	}

	return m, nil
}
