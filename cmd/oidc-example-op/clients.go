package main

import (
	"fmt"
	"strings"
)

type client struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Public       bool
}

type staticClients []client

func (s staticClients) IsValidClientID(clientID string) (ok bool, err error) {
	for _, c := range s {
		if c.ClientID == clientID {
			return true, nil
		}
	}
	return false, nil
}

func (s staticClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s staticClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	for _, c := range s {
		if c.ClientID == clientID && c.ClientSecret == clientSecret {
			return true, nil
		}
	}
	return false, nil
}

func (s staticClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	var cl *client
	for _, c := range s {
		if c.ClientID == clientID {
			cl = &c
		}
	}
	if cl == nil {
		return false, fmt.Errorf("invalid client")
	}
	if cl.RedirectURL == redirectURI {
		return true, nil
	}
	if cl.Public && strings.HasPrefix(redirectURI, "http://localhost") { // hacky but probably fine here
		return true, nil
	}
	return false, nil
}
