package main

import (
	"log"
	"net/http"
	"time"

	"github.com/pardot/oidc/core"
)

func main() {
	smgr := newStubSMGR()

	oidc, err := core.New(&core.Config{
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, smgr, &staticClients{}, mustInitSigner())
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	svr := &server{
		oidc:    oidc,
		storage: smgr,
	}

	log.Printf("Listening on: %s", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", svr)
	if err != nil {
		log.Fatal(err)
	}
}
