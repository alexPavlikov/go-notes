package db

import (
	"context"

	"github.com/alexPavlikov/go-notes/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(ctx context.Context, cfg *config.Config) (pool *pgxpool.Pool, err error) {
	// pool, err = pgxpool.New(ctx, fmt.Sprintf("postgres://%s:%d@%s:%s/%s", cfg.Postgres.Path, cfg.Postgres.Port, cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.DBName))
	// if err != nil {
	// 	return nil, err
	// }

	return pool, nil
}
