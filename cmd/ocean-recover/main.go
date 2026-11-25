package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Weichwolf/ocean/internal/controlplane"
)

func main() {
	config := flag.String("config", "", "regional configuration for the restored metadata store")
	tenant := flag.String("tenant", "", "tenant that owns the share")
	subscription := flag.String("subscription", "", "subscription that owns the share")
	share := flag.String("share", "", "ARM file share resource ID")
	output := flag.String("output", "", "new private key file")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := controlplane.RecoverVolumeKey(ctx, *config, *tenant, *subscription, *share, *output); err != nil {
		fmt.Fprintln(os.Stderr, "ocean-recover:", err)
		os.Exit(1)
	}
}
