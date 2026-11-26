package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Weichwolf/ocean/internal/rack"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ocean-rack:", err)
		os.Exit(1)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	options := flag.NewFlagSet("ocean-rack", flag.ContinueOnError)
	options.SetOutput(diagnostics)
	inventoryFile := options.String("inventory", "", "signed rack inventory JSON file")
	signatureFile := options.String("signature", "", "detached inventory signature file")
	publicKeyFile := options.String("public-key", "", "trusted Ed25519 PEM public key")
	hostID := options.String("host", "", "inventory host to verify")
	caFile := options.String("bmc-ca", "", "BMC TLS CA bundle")
	credentialFile := options.String("bmc-credential", "", "private JSON file containing BMC credentials")
	ironicOrigin := options.String("ironic-origin", "", "Ironic HTTPS origin")
	ironicCA := options.String("ironic-ca", "", "Ironic TLS CA bundle")
	ironicToken := options.String("ironic-token", "", "private file containing an Ironic API token")
	if err := options.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if options.NArg() != 0 || *inventoryFile == "" || *signatureFile == "" || *publicKeyFile == "" ||
		*hostID == "" || *caFile == "" || *credentialFile == "" || *ironicOrigin == "" || *ironicCA == "" || *ironicToken == "" {
		options.Usage()
		return errors.New("inventory, host, BMC and Ironic flags are required")
	}
	inventory, err := rack.LoadInventory(*inventoryFile, *signatureFile, *publicKeyFile, time.Now())
	if err != nil {
		return err
	}
	for _, asset := range inventory.Assets {
		if asset.HostID != *hostID {
			continue
		}
		redfish, err := rack.OpenRedfish(*caFile, *credentialFile)
		if err != nil {
			return err
		}
		ironic, err := rack.OpenIronic(*ironicOrigin, *ironicCA, *ironicToken)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := redfish.Verify(ctx, asset); err != nil {
			return err
		}
		if err := ironic.Verify(ctx, asset); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			HostID   string `json:"hostId"`
			Rack     string `json:"rack"`
			NodeID   string `json:"ironicNodeId"`
			Revision uint64 `json:"inventoryRevision"`
		}{HostID: asset.HostID, Rack: asset.Rack, NodeID: asset.NodeID, Revision: inventory.Revision})
	}
	return errors.New("host is absent from the approved rack inventory")
}
