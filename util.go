package deci

import (
	"net/url"
	"path"
)

func absPath(base url.URL, pathItems ...string) string {
	paths := make([]string, len(pathItems)+1)
	paths[0] = base.Path
	copy(paths[1:], pathItems)
	return path.Join(paths...)
}

func absURL(base url.URL, pathItems ...string) string {
	u := base
	u.Path = absPath(base, pathItems...)
	return u.String()
}
