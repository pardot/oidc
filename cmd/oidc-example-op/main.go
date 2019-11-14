package main

import (
	"log"
	"net/http"
	"time"

	"github.com/pardot/oidc/core"
	"github.com/pardot/oidc/storage/memory"
)

func main() {
	oidc, err := core.NewOIDC(&core.Config{
		AuthValidityTime:        5 * time.Minute,
		CodeValidityTime:        5 * time.Minute,
		AccessTokenValidityTime: 5 * time.Minute,
	}, memory.New(), &staticClients{}, nil)
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	svr := &server{
		oidc: oidc,
	}

	log.Printf("Listening on: %s", "127.0.0.1:8085")
	err = http.ListenAndServe("127.0.0.1:8085", svr)
	if err != nil {
		log.Fatal(err)
	}
}
