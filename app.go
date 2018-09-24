package deci

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

type App struct {
	router  *mux.Router
	session sessions.Store
}

func NewApp(session sessions.Store) *App {
	router := mux.NewRouter()

	return &App{
		router:  router,
		session: session,
	}
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}
