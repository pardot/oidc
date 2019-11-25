package main

import (
	"fmt"
	"html/template"
	"log"
	"sync"

	"net/http"

	"github.com/pardot/oidc/core"
)

const (
	sessIDCookie = "sessID"
)

type server struct {
	oidc     *core.OIDC
	mux      *http.ServeMux
	muxSetup sync.Once
	storage  *storage
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
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var loginTmpl = template.Must(template.New("loginPage").Parse(loginPage))

func (s *server) authorization(w http.ResponseWriter, req *http.Request) {
	ar, err := s.oidc.StartAuthorization(w, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("error starting authorization flow: %v", err), http.StatusInternalServerError)
		return
	}

	// set a cookie with the auth ID, so we can track it. Note - this should
	// _never_ be done in a real application. The auth ID should generally be
	// kept secret from the user, and the user should not be able to pass one
	// directly.
	aidc := &http.Cookie{
		Name:   sessIDCookie,
		Value:  ar.SessionID,
		MaxAge: 60,
	}
	http.SetCookie(w, aidc)

	tmplData := map[string]interface{}{}

	if err := loginTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) finishAuthorization(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusInternalServerError)
		return
	}

	sessID, err := req.Cookie(sessIDCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get auth id cookie: %v", err), http.StatusInternalServerError)
		return
	}

	// We have the session ID. This is stable for the session, so we can track
	// whatever we want along with it. We always get the session ID in later
	// requests, so we can always pull things out
	meta := &metadata{}
	s.storage.sessions[sessID.Value].Meta = meta

	// finalize it. this will redirect the user to the appropriate place
	if err := s.oidc.FinishAuthorization(w, req, sessID.Value, []string{}); err != nil {
		log.Printf("error finishing authorization: %v", err)
	}
}

func (s *server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		// This is how we could update our metadata
		meta := s.storage.sessions[tr.SessionID].Meta
		s.storage.sessions[tr.SessionID].Meta = meta

		idt := core.IDToken{}

		return &core.TokenResponse{
			AllowRefresh: false,
			IDToken:      idt,
		}, nil
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("error in token endpoint: %v", err), http.StatusInternalServerError)
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
