package rack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"
)

type Ironic struct {
	client    *http.Client
	origin    string
	tokenFile string
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
	if _, err := readIronicToken(tokenFile); err != nil {
		return nil, err
	}
	return &Ironic{client: client, origin: origin, tokenFile: tokenFile}, nil
}

func readIronicToken(tokenFile string) (string, error) {
	raw, err := readBounded(tokenFile, 16<<10, true)
	if err != nil {
		return "", fmt.Errorf("read Ironic credentials: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", errors.New("invalid Ironic token file")
	}
	return token, nil
}

type IronicImage struct {
	Source         string `json:"image_source"`
	Algo           string `json:"image_os_hash_algo"`
	SHA256         string `json:"image_os_hash_value"`
	DownloadSource string `json:"image_download_source"`
}

type IronicNode struct {
	UUID           string         `json:"uuid"`
	State          string         `json:"provision_state"`
	Target         string         `json:"target_provision_state"`
	Instance       string         `json:"instance_uuid"`
	ResourceClass  string         `json:"resource_class"`
	Inspection     time.Time      `json:"inspection_finished_at"`
	InspectionMode string         `json:"inspect_interface"`
	Management     string         `json:"management_interface"`
	Power          string         `json:"power_interface"`
	Storage        string         `json:"storage_interface"`
	Maintenance    bool           `json:"maintenance"`
	InstanceInfo   map[string]any `json:"instance_info"`
	Properties     struct {
		Cores   int    `json:"cpus"`
		Memory  int    `json:"memory_mb"`
		Disk    int    `json:"local_gb"`
		CPUArch string `json:"cpu_arch"`
	} `json:"properties"`
}

func (image IronicImage) Matches(node IronicNode) bool {
	return node.InstanceInfo["image_source"] == image.Source &&
		node.InstanceInfo["image_os_hash_algo"] == image.Algo && node.InstanceInfo["image_os_hash_value"] == image.SHA256 &&
		node.InstanceInfo["image_download_source"] == image.DownloadSource
}

// Verify checks that the site service will target the approved BMC and boot NIC.
func (i *Ironic) Verify(ctx context.Context, asset Asset) error {
	_, err := i.VerifiedNode(ctx, asset)
	return err
}

func (i *Ironic) VerifiedNode(ctx context.Context, asset Asset) (IronicNode, error) {
	if !asset.valid() {
		return IronicNode{}, errors.New("invalid rack asset")
	}
	resource := "/v1/nodes/" + asset.NodeID
	var node struct {
		IronicNode
		Driver     string `json:"driver"`
		DriverInfo struct {
			BMC      string          `json:"redfish_address"`
			System   string          `json:"redfish_system_id"`
			VerifyCA json.RawMessage `json:"redfish_verify_ca"`
			BootMode string          `json:"force_persistent_boot_device"`
		} `json:"driver_info"`
		Boot   string `json:"boot_interface"`
		Deploy string `json:"deploy_interface"`
	}
	if err := i.get(ctx, resource, &node); err != nil {
		return IronicNode{}, err
	}
	if node.UUID != asset.NodeID || node.Driver != "redfish" || node.DriverInfo.BMC != asset.BMC || node.DriverInfo.System != asset.System {
		return IronicNode{}, errors.New("Ironic node does not bind the approved Redfish system")
	}
	if !ironicVerifiesCA(node.DriverInfo.VerifyCA) || (node.Boot != "pxe" && node.Boot != "ipxe") || node.Deploy != "direct" ||
		(node.DriverInfo.BootMode != "" && !strings.EqualFold(node.DriverInfo.BootMode, "Default")) {
		return IronicNode{}, errors.New("Ironic node is outside the verified Redfish, one-time PXE and direct-deploy profile")
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
		return IronicNode{}, err
	}
	if ports.Next != "" || len(ports.Ports) > 100 {
		return IronicNode{}, errors.New("Ironic node port inventory exceeds the verified profile")
	}
	bootPorts := 0
	for _, port := range ports.Ports {
		if !port.PXEEnabled {
			continue
		}
		mac, err := net.ParseMAC(port.Address)
		if port.NodeID != asset.NodeID || err != nil || mac.String() != asset.BootMAC {
			return IronicNode{}, errors.New("Ironic enables PXE on a port outside the approved boot identity")
		}
		bootPorts++
	}
	if bootPorts != 1 {
		return IronicNode{}, errors.New("Ironic requires exactly one approved PXE-enabled port")
	}
	return node.IronicNode, nil
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
	req, err := i.request(ctx, http.MethodGet, resource, "", nil)
	if err != nil {
		return err
	}
	return readManagementJSON(i.client, req, "Ironic", result)
}

func (i *Ironic) request(ctx context.Context, method, resource, contentType string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, i.origin+resource, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid Ironic request")
	}
	token, err := readIronicToken(i.tokenFile)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("X-OpenStack-Ironic-API-Version", "1.56")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req, nil
}
