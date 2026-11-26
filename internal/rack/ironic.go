package rack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"unicode"
)

type Ironic struct {
	client *http.Client
	origin string
	token  string
}

// OpenIronic connects to the site's Ironic API using a private Keystone token file.
func OpenIronic(origin, caFile, tokenFile string) (*Ironic, error) {
	if !validOrigin(origin) {
		return nil, errors.New("Ironic endpoint must be an HTTPS origin")
	}
	client, err := managementClient(caFile)
	if err != nil {
		return nil, fmt.Errorf("configure Ironic TLS: %w", err)
	}
	raw, err := readBounded(tokenFile, 16<<10, true)
	if err != nil {
		return nil, fmt.Errorf("read Ironic credentials: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, errors.New("invalid Ironic token file")
	}
	return &Ironic{client: client, origin: origin, token: token}, nil
}

// Verify checks that the site service will target the approved BMC and boot NIC.
func (i *Ironic) Verify(ctx context.Context, asset Asset) error {
	if !asset.valid() {
		return errors.New("invalid rack asset")
	}
	resource := "/v1/nodes/" + asset.NodeID
	var node struct {
		UUID       string `json:"uuid"`
		Driver     string `json:"driver"`
		DriverInfo struct {
			BMC      string          `json:"redfish_address"`
			System   string          `json:"redfish_system_id"`
			VerifyCA json.RawMessage `json:"redfish_verify_ca"`
		} `json:"driver_info"`
		Boot   string `json:"boot_interface"`
		Deploy string `json:"deploy_interface"`
	}
	if err := i.get(ctx, resource, &node); err != nil {
		return err
	}
	if node.UUID != asset.NodeID || node.Driver != "redfish" || node.DriverInfo.BMC != asset.BMC || node.DriverInfo.System != asset.System {
		return errors.New("Ironic node does not bind the approved Redfish system")
	}
	if !ironicVerifiesCA(node.DriverInfo.VerifyCA) || (node.Boot != "pxe" && node.Boot != "ipxe") || node.Deploy != "direct" {
		return errors.New("Ironic node is outside the verified Redfish, PXE and direct-deploy profile")
	}
	var ports struct {
		Ports []struct {
			NodeID     string `json:"node_uuid"`
			Address    string `json:"address"`
			PXEEnabled bool   `json:"pxe_enabled"`
		} `json:"ports"`
		Next string `json:"next"`
	}
	if err := i.get(ctx, resource+"/ports/detail?limit=100", &ports); err != nil {
		return err
	}
	if ports.Next != "" || len(ports.Ports) > 100 {
		return errors.New("Ironic node port inventory exceeds the verified profile")
	}
	bootPorts := 0
	for _, port := range ports.Ports {
		if !port.PXEEnabled {
			continue
		}
		mac, err := net.ParseMAC(port.Address)
		if port.NodeID != asset.NodeID || err != nil || mac.String() != asset.BootMAC {
			return errors.New("Ironic enables PXE on a port outside the approved boot identity")
		}
		bootPorts++
	}
	if bootPorts != 1 {
		return errors.New("Ironic requires exactly one approved PXE-enabled port")
	}
	return nil
}

func ironicVerifiesCA(setting json.RawMessage) bool {
	// Ironic's Redfish driver verifies certificates by default.
	if len(setting) == 0 || string(setting) == "true" {
		return true
	}
	var certificatePath string
	return json.Unmarshal(setting, &certificatePath) == nil && path.IsAbs(certificatePath)
}

func (i *Ironic) get(ctx context.Context, resource string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, i.origin+resource, nil)
	if err != nil {
		return errors.New("invalid Ironic request")
	}
	req.Header.Set("X-Auth-Token", i.token)
	req.Header.Set("X-OpenStack-Ironic-API-Version", "1.56")
	return readManagementJSON(i.client, req, "Ironic", result)
}
