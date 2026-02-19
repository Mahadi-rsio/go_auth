package cache

import "github.com/redis/go-redis/v9"

var RedisClient *redis.Client

func Initialize(url string) {
	RedisClient = redis.NewClient(&redis.Options{
		Addr: url,
	})
}
