package main

import (
	"os"

	"github.com/Weichwolf/ocean/internal/desktopgateway"
	"github.com/Weichwolf/ocean/internal/service"
)

func main() {
	os.Exit(service.Main("desktop-gateway", desktopgateway.Load))
}
