package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"sync"

	"net/http"

	"golang.org/x/oauth2"
)

const (
	stateCookie = "state"
)

type server struct {
	oa2cfg   *oauth2.Config
	mux      *http.ServeMux
	muxSetup sync.Once
}

const homePage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<h1>Start auth flow</h1>
		<form action="/start" method="POST">
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var homeTmpl = template.Must(template.New("loginPage").Parse(homePage))

func (s *server) home(w http.ResponseWriter, req *http.Request) {
	tmplData := map[string]interface{}{}

	if err := homeTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

// start the actual flow. this builds up the request and sends the user on
func (s *server) start(w http.ResponseWriter, req *http.Request) {
	// track a random state var to prevent CSRF
	state := mustRandStr(16)
	sc := &http.Cookie{
		Name:   stateCookie,
		Value:  state,
		MaxAge: 60,
	}
	http.SetCookie(w, sc)

	http.Redirect(w, req, s.oa2cfg.AuthCodeURL(state), http.StatusSeeOther)
}

const callbackPage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<div>access_token: {{ .access_token }}</div>
		<div>id_token: {{ .id_token }}</div>
	</body>
</html>`

var callbackTmpl = template.Must(template.New("loginPage").Parse(callbackPage))

func (s *server) callback(w http.ResponseWriter, req *http.Request) {
	statec, err := req.Cookie(stateCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get state cookie: %v", err), http.StatusInternalServerError)
		return
	}

	if errMsg := req.FormValue("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("error returned to callback %s: %s", errMsg, req.FormValue("error_description")), http.StatusInternalServerError)
		return
	}

	code := req.FormValue("code")
	if code == "" {
		http.Error(w, "no code in callback response", http.StatusBadRequest)
		return
	}

	gotState := req.FormValue("state")
	if gotState == "" || gotState != statec.Value {
		http.Error(w, fmt.Sprintf("returned state %q doesn't match request state %q", gotState, statec.Value), http.StatusBadRequest)
		return
	}

	oa2Tok, err := s.oa2cfg.Exchange(req.Context(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("error exchanging code %q for token: %v", code, err), http.StatusInternalServerError)
	}

	rawIDToken, ok := oa2Tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token included in response", http.StatusBadRequest)
	}

	tmplData := map[string]interface{}{
		"access_token": oa2Tok.AccessToken,
		"id_token":     rawIDToken,
	}

	if err := callbackTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.muxSetup.Do(func() {
		s.mux = http.NewServeMux()
		s.mux.HandleFunc("/", s.home)
		s.mux.HandleFunc("/start", s.start)
		s.mux.HandleFunc("/callback", s.callback)
	})

	s.mux.ServeHTTP(w, req)
}

func mustRandStr(len int) string {
	b := make([]byte, len)
	if r, err := rand.Read(b); err != nil || r != len {
		panic("error or underread from rand.Read")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
