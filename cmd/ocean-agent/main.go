package main

import (
	"os"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/nodeagent"
	"github.com/Weichwolf/ocean/internal/service"
)

func main() {
	os.Exit(service.Main("node-agent", func(path string) (config.Server, service.Hooks, error) {
		settings, err := config.LoadServer(path, "127.0.0.1:8081")
		return settings, service.Hooks{Startup: nodeagent.CheckRuntime}, err
	}))
}
