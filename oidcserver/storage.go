package oidcserver

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"strings"
)

const (
	authReqKeyspace         = "auth-request"
	authCodeKeyspace        = "auth-code"
	refreshTokenKeyspace    = "refresh-token"
	offlineSessionsKeyspace = "offline-session"
)

// Kubernetes only allows lower case letters for names.
//
// TODO(ericchiang): refactor ID creation onto the storage.
var encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

// NewID returns a random string which can be used as an ID for objects.
func NewID() string {
	buff := make([]byte, 16) // 128 bit random ID.
	if _, err := io.ReadFull(rand.Reader, buff); err != nil {
		panic(err)
	}
	// Avoid the identifier to begin with number and trim padding
	return string(buff[0]%26+'a') + strings.TrimRight(encoding.EncodeToString(buff[1:]), "=")
}
