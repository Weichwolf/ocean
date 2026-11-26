package main

import (
	"os"

	"github.com/Weichwolf/ocean/internal/controlplane"
	"github.com/Weichwolf/ocean/internal/service"
)

func main() { os.Exit(service.Main("federation", controlplane.LoadFederation)) }
