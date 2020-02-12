package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"strings"
	"sync"
	"time"

	"net/http"

	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"
)

type server struct {
	oidc            *core.OIDC
	mux             *http.ServeMux
	muxSetup        sync.Once
	storage         *storage
	tokenValidFor   time.Duration
	refreshValidFor time.Duration
}

const loginPage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<h1>Log in to IDP</h1>
		<form action="/finish" method="POST">
			<p>Subject: <input type="text" name="subject" value="auser" required size="15"></p>
			<p>Granted Scopes (space delimited): <input type="text" name="scopes" value="{{ .scopes }}" size="15"></p>
			<p>ACR: <input type="text" name="acr" size="15"></p>
			<p>AMR (comma delimited): <input type="text" name="amr" value="{{ .amr }}" size="15"></p>
			<p>Userinfo: <textarea name="userinfo" rows="10" cols="30">{"name": "A User"}</textarea></p>
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var loginTmpl = template.Must(template.New("loginPage").Parse(loginPage))

func (s *server) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidc.StartAuthorization(w, req)
	if err != nil {
		return
	}

	// set a cookie with the auth ID, so we can track it.
	aidc := &http.Cookie{
		Name:   sessIDCookie,
		Value:  ar.SessionID,
		MaxAge: 600,
	}
	http.SetCookie(w, aidc)

	var acr string
	if len(ar.ACRValues) > 0 {
		acr = ar.ACRValues[0]
	}
	tmplData := map[string]interface{}{
		"acr":    acr,
		"scopes": strings.Join(ar.Scopes, " "),
	}

	if err := loginTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) finishAuthorization(w http.ResponseWriter, req *http.Request) {
	sessID, err := req.Cookie(sessIDCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get auth id cookie: %v", err), http.StatusInternalServerError)
		return
	}

	var amr []string
	if req.FormValue("amr") != "" {
		amr = strings.Split(req.FormValue("amr"), ",")
	}

	auth := &core.Authorization{
		Scopes: strings.Split(req.FormValue("scopes"), " "),
		ACR:    req.FormValue("acr"),
		AMR:    amr,
	}

	// We have the session ID. This is stable for the session, so we can track
	// whatever we want along with it. We always get the session ID in later
	// requests, so we can always pull things out

	meta := &metadata{
		Subject:  req.FormValue("subject"),
		Userinfo: map[string]interface{}{},
	}
	if err := json.Unmarshal([]byte(req.FormValue("userinfo")), &meta.Userinfo); err != nil {
		http.Error(w, fmt.Sprintf("failed to unmarshal userinfo: %v", err), http.StatusInternalServerError)
		return
	}
	s.storage.sessions[sessID.Value].Meta = meta

	// finalize it. this will redirect the user to the appropriate place
	if err := s.oidc.FinishAuthorization(w, req, sessID.Value, auth); err != nil {
		log.Printf("error finishing authorization: %v", err)
	}
}

func (s *server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		// This is how we could update our metadata
		meta := s.storage.sessions[tr.SessionID].Meta
		s.storage.sessions[tr.SessionID].Meta = meta

		idt := tr.PrefillIDToken("http://localhost:8085", "subject", time.Now().Add(s.tokenValidFor))

		return &core.TokenResponse{
			AccessTokenValidUntil:  time.Now().Add(s.tokenValidFor),
			RefreshTokenValidUntil: time.Now().Add(s.refreshValidFor),
			IssueRefreshToken:      tr.SessionRefreshable, // always allow it if we want it
			IDToken:                idt,
		}, nil
	})
	if err != nil {
		log.Printf("error in token endpoint: %v", err)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.muxSetup.Do(func() {
		s.mux = http.NewServeMux()
		s.mux.HandleFunc("/auth", s.authorization)
		s.mux.HandleFunc("/finish", s.finishAuthorization)
		s.mux.HandleFunc("/token", s.token)
	})

	s.mux.ServeHTTP(w, req)
}
