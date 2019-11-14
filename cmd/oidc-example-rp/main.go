package main

import (
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

func main() {
	oidcSvrAddr := "http://127.0.0.1:8085"

	oa2cfg := oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://127.0.0.1:8084/callback",

		Endpoint: oauth2.Endpoint{
			AuthURL:  oidcSvrAddr + "/auth",
			TokenURL: oidcSvrAddr + "/token",
		},

		Scopes: []string{"openid"},
	}

	svr := &server{
		oa2cfg: &oa2cfg,
	}

	log.Printf("Listening on: %s", "127.0.0.1:8084")
	err := http.ListenAndServe("127.0.0.1:8084", svr)
	if err != nil {
		log.Fatal(err)
	}
}
