package main

import (
	"api/config"
	"api/src/repositories"
)

func main() {
	config.Load()
	repositories.CreateDB(config.AppConfig.DBPath)
	//cache.Initialize(config.AppConfig.RdisURL)
	Router(config.AppConfig.Port)
}
