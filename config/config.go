package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	Port      string
	DBPath    string
	RdisURL   string
	DebugMode bool
}

var AppConfig *Config

func Load() {
	required := []string{"PORT", "DB_PATH", "REDIS_URL"}

	values := make(map[string]string)
	for _, key := range required {
		val := os.Getenv(key)
		if val == "" {
			log.Fatalf("Environment variable %s is required but not set", key)
		}
		values[key] = val
	}

	debug := false
	if val := os.Getenv("DEBUG"); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			log.Fatalf("Invalid value for DEBUG: %s", val)
		}
		debug = parsed
	}

	AppConfig = &Config{
		Port:      values["PORT"],
		DBPath:    values["DB_PATH"],
		RdisURL:   values["REDIS_URL"],
		DebugMode: debug,
	}

	log.Printf("Configuration loaded: %+v\n", AppConfig)
}
