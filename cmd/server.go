package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexPavlikov/go-notes/internal/config"
	"github.com/alexPavlikov/go-notes/internal/db"
	redisstorage "github.com/alexPavlikov/go-notes/internal/redis"
	"github.com/alexPavlikov/go-notes/internal/repository"
	"github.com/alexPavlikov/go-notes/internal/server"
	"github.com/alexPavlikov/go-notes/internal/server/locations"
	"github.com/alexPavlikov/go-notes/internal/service"
)

func Run() error {

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("confg load err: %w", err)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(cfg.DBConnectTimeout))
	defer cancel()

	pool, err := db.Connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect to postgres err : %w", err)
	}

	redis := redisstorage.Connect(cfg.Redis.ToString(), cfg.Redis.Password, cfg.Redis.DB)

	repo := repository.New(pool)
	services := service.New(repo, redis, cfg)
	handler := locations.New(services)
	router := server.New(handler)

	slog.Info(fmt.Sprintf("server listen on %s", cfg.Server.ToString()))

	srv := &http.Server{
		Addr:              cfg.Server.ToString(),
		Handler:           router.Build(),
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("start http serve error: %w", err)
	}

	return nil
}
