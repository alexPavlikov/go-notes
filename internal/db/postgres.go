package db

import (
	"context"
	"fmt"

	"github.com/alexPavlikov/go-notes/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(ctx context.Context, cfg *config.Config) (pool *pgxpool.Pool, err error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Path, cfg.Postgres.Port, cfg.Postgres.DBName)

	pool, err = pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}

	return pool, nil
}
