package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/federation"
)

func main() {
	file := flag.String("config", "", "farm routing JSON configuration")
	path := flag.String("path", "", "local WireGuard gateway path")
	var router netip.Addr
	flag.TextVar(&router, "router", netip.Addr{}, "local fabric router IPv4 address")
	flag.Parse()
	if *file == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := config.Load(*file, federation.RoutingConfig{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	output, err := federation.BIRDConfig(cfg, *path, router)
	if err == nil {
		_, err = fmt.Fprint(os.Stdout, output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
