package server

import (
	"net/http"
	"time"

	"github.com/alexPavlikov/go-notes/internal/server/locations"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type Router struct {
	Handler *locations.Handler
}

func New(handler *locations.Handler) *Router {
	return &Router{
		Handler: handler,
	}
}

func (r *Router) Build() http.Handler {
	router := chi.NewRouter()

	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(2 * time.Second))

	router.Post("/v1/add_note", r.Handler.AddNote)
	router.Get("/v1/get_notes", r.Handler.GetNotes)

	router.Post("/v1/auth", r.Handler.Auth)
	router.Post("/v1/refresh", r.Handler.Refresh)

	return router
}
