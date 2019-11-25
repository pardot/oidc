package main

type staticClients struct{}

func (s *staticClients) IsValidClientID(clientID string) (ok bool, err error) {
	if clientID == "client-id" {
		return true, nil
	}
	return false, nil
}

func (s *staticClients) IsUnauthenticatedClient(clientID string) (ok bool, err error) {
	return false, nil
}

func (s *staticClients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	if clientID == "client-id" && clientSecret == "client-secret" {
		return true, nil
	}
	return false, nil
}

func (s *staticClients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	if clientID == "client-id" && redirectURI == "http://localhost:8084/callback" {
		return true, nil
	}
	return false, nil
}
