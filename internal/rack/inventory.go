// Package rack verifies provisionable bare-metal assets against the site's inventory.
package rack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
)

const inventoryLimit = 4 << 20

var (
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	redfishPath  = regexp.MustCompile(`^/redfish/v1/[a-zA-Z0-9.~/!_:-]+$`)
)

type Inventory struct {
	Revision  uint64    `json:"revision"`
	NotBefore time.Time `json:"notBefore"`
	ExpiresAt time.Time `json:"expiresAt"`
	Assets    []Asset   `json:"assets"`
}

type Asset struct {
	HostID  string `json:"hostId"`
	Rack    string `json:"rack"`
	NodeID  string `json:"ironicNodeId"`
	BMC     string `json:"bmcOrigin"`
	System  string `json:"redfishSystem"`
	Serial  string `json:"serial"`
	UUID    string `json:"systemUuid"`
	BootMAC string `json:"bootMac"`
}

// LoadInventory verifies the detached signature over the exact JSON bytes.
func LoadInventory(inventoryFile, signatureFile, publicKeyFile string, now time.Time) (Inventory, error) {
	raw, err := readBounded(inventoryFile, inventoryLimit, false)
	if err != nil {
		return Inventory{}, fmt.Errorf("read rack inventory: %w", err)
	}
	signatureText, err := readBounded(signatureFile, 256, false)
	if err != nil {
		return Inventory{}, fmt.Errorf("read rack inventory signature: %w", err)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Inventory{}, errors.New("rack inventory signature must be base64-encoded Ed25519")
	}
	publicPEM, err := readBounded(publicKeyFile, 4096, false)
	if err != nil {
		return Inventory{}, fmt.Errorf("read rack inventory public key: %w", err)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return Inventory{}, errors.New("rack inventory requires one PEM public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Inventory{}, fmt.Errorf("parse rack inventory public key: %w", err)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(public, raw, signature) {
		return Inventory{}, errors.New("rack inventory signature verification failed")
	}
	inventory, err := config.Decode(bytes.NewReader(raw), Inventory{})
	if err != nil {
		return Inventory{}, err
	}
	if inventory.Revision == 0 || inventory.NotBefore.IsZero() || now.Before(inventory.NotBefore) || !now.Before(inventory.ExpiresAt) {
		return Inventory{}, errors.New("rack inventory is outside its signed validity interval or has no revision")
	}
	if err := inventory.validate(); err != nil {
		return Inventory{}, err
	}
	return inventory, nil
}

func (i Inventory) validate() error {
	hosts := make(map[string]bool)
	nodes := make(map[string]bool)
	macs := make(map[string]bool)
	uuids := make(map[string]bool)
	systems := make(map[string]bool)
	for _, asset := range i.Assets {
		if !asset.valid() {
			return errors.New("rack inventory contains an invalid asset")
		}
		system := asset.BMC + asset.System
		if hosts[asset.HostID] || nodes[asset.NodeID] || macs[asset.BootMAC] || uuids[asset.UUID] || systems[system] {
			return errors.New("rack inventory contains a duplicate hardware or host identity")
		}
		hosts[asset.HostID], nodes[asset.NodeID], macs[asset.BootMAC], uuids[asset.UUID], systems[system] = true, true, true, true, true
	}
	return nil
}

func (a Asset) valid() bool {
	mac, err := net.ParseMAC(a.BootMAC)
	if err != nil || len(mac) != 6 || mac.String() != a.BootMAC || mac[0]&1 != 0 || a.BootMAC == "00:00:00:00:00:00" {
		return false
	}
	return labelPattern.MatchString(a.HostID) && labelPattern.MatchString(a.Rack) && validUUID(a.NodeID) &&
		validUUID(a.UUID) && a.Serial != "" && strings.TrimSpace(a.Serial) == a.Serial && len(a.Serial) <= 256 &&
		validOrigin(a.BMC) && validRedfishPath(a.System) && strings.HasPrefix(a.System, "/redfish/v1/Systems/") &&
		path.Dir(a.System) == "/redfish/v1/Systems"
}

func validUUID(value string) bool {
	return uuidPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000" &&
		value != "ffffffff-ffff-ffff-ffff-ffffffffffff"
}

func validOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Path == "" &&
		u.Fragment == "" && u.RawQuery == "" && !u.ForceQuery && value == "https://"+u.Host
}

func validRedfishPath(value string) bool {
	return redfishPath.MatchString(value) && path.Clean(value) == value
}

func readBounded(filename string, limit int64, private bool) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("expected a regular file with owner-only permissions for credentials")
	}
	if info.Size() > limit {
		return nil, errors.New("rack configuration file exceeds its size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err == nil && int64(len(raw)) > limit {
		return nil, errors.New("rack configuration file exceeds its size limit")
	}
	return raw, err
}
