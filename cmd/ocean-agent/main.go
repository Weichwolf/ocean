package main

import (
	"os"

	"github.com/Weichwolf/ocean/internal/nodeagent"
	"github.com/Weichwolf/ocean/internal/service"
)

func main() {
	os.Exit(service.Main("node-agent", "127.0.0.1:8081", nodeagent.CheckRuntime))
}
