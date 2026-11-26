package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/federation"
)

func main() {
	file := flag.String("config", "", "geo HTTPS ingress JSON configuration")
	flag.Parse()
	if *file == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := config.Load(*file, federation.GeoIngressConfig{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	output, err := federation.GeoIngressHAProxy(cfg)
	if err == nil {
		_, err = fmt.Fprint(os.Stdout, output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
