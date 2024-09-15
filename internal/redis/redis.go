package redisstorage

import (
	"github.com/redis/go-redis/v9"
)

func Connect(addr string, password string, db int) *redis.Client {
	rds := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	return rds
}

func RemoteConnect() *redis.Client {
	url := "redis://default:AweshmPZMWuzBZRVtlyNLLRQdMAdSNuN@redis-15324.c302.asia-northeast1-1.gce.redns.redis-cloud.com:15324"
	opt, err := redis.ParseURL(url)
	if err != nil {
		panic(err)
	}

	// opt.DialTimeout = 5 * time.Second
	// opt.ReadTimeout = 3 * time.Second
	// opt.WriteTimeout = 3 * time.Second
	// opt.PoolTimeout = 6 * time.Second
	// opt.MinRetryBackoff = 1 * time.Second
	// opt.MaxRetryBackoff = 5 * time.Second
	// opt.MaxRetries = 5

	return redis.NewClient(opt)
}
