package redisstorage

import "github.com/redis/go-redis/v9"

func Connect(addr string, password string, db int) *redis.Client {
	rds := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return rds
}
