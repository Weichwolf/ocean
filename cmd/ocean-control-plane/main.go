package main

import (
	"os"

	"github.com/Weichwolf/ocean/internal/service"
)

func main() {
	os.Exit(service.Main("control-plane", "127.0.0.1:8080", nil))
}
