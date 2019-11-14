package main

import (
	"fmt"
	"html/template"
	"log"
	"sync"
	"time"

	"net/http"

	"github.com/golang/protobuf/ptypes"
	"github.com/pardot/oidc/core"
	examplestate "github.com/pardot/oidc/proto/deci/example/v1beta1"
)

const (
	authIDCookie = "authID"
)

type server struct {
	oidc     *core.OIDC
	mux      *http.ServeMux
	muxSetup sync.Once
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
		Name:   authIDCookie,
		Value:  ar.AuthID,
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

	authID, err := req.Cookie(authIDCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get auth id cookie: %v", err), http.StatusInternalServerError)
		return
	}

	// get the form values, fill in the details
	claims := core.NewClaims("iss", "sub", "aud", time.Now().Add(5*time.Minute), time.Now())

	// This is what we track, and will get back in the token response
	meta := &examplestate.User{}

	// finalize it. this will redirect the user to the appropriate place
	if err := s.oidc.FinishAuthorization(w, req, authID.Value, []string{}, claims, meta); err != nil {
		log.Printf("error finishing authorization: %v", err)
	}
}

func (s *server) token(w http.ResponseWriter, req *http.Request) {
	err := s.oidc.Token(w, req, func(tr *core.TokenRequest) (*core.TokenResponse, error) {
		meta := &examplestate.User{}

		if err := ptypes.UnmarshalAny(tr.Metadata, meta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		claims := tr.Claims

		metaany, err := ptypes.MarshalAny(meta)
		if err != nil {
			return nil, fmt.Errorf("failed to marhal metadata: %w", err)
		}

		return &core.TokenResponse{
			AllowRefresh: false,
			Claims:       claims,
			Metadata:     metaany,
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
