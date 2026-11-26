package rack

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

type InstallationConfig struct {
	EnrollmentOrigin  string `json:"enrollmentOrigin"`
	EnrollmentCAFile  string `json:"enrollmentCAFile"`
	CredentialKeyFile string `json:"credentialKeyFile"`
	DebianImageURL    string `json:"debianImageURL"`
	DebianImageSHA256 string `json:"debianImageSHA256"`
	AgentPackageURL   string `json:"agentPackageURL"`
	AgentSHA256       string `json:"agentPackageSHA256"`
	PackageCAFile     string `json:"packageCAFile,omitempty"`
	ResourceClass     string `json:"ironicResourceClass"`
	MinimumDiskGiB    int    `json:"minimumDiskGiB"`
	CPUArchitecture   string `json:"cpuArchitecture"`
}

type Installation struct {
	Config    InstallationConfig
	Image     IronicImage
	Digest    string
	ca        []byte
	packageCA []byte
	key       []byte
}

func OpenInstallation(cfg InstallationConfig) (*Installation, error) {
	if !validOrigin(cfg.EnrollmentOrigin) || !httpsArtifact(cfg.DebianImageURL) || !httpsArtifact(cfg.AgentPackageURL) ||
		!validSHA256(cfg.DebianImageSHA256) || !validSHA256(cfg.AgentSHA256) ||
		cfg.ResourceClass == "" || len(cfg.ResourceClass) > 80 || cfg.MinimumDiskGiB < 1 ||
		(cfg.CPUArchitecture != "x86_64" && cfg.CPUArchitecture != "aarch64") {
		return nil, errors.New("invalid rack installation profile")
	}
	ca, err := readBounded(cfg.EnrollmentCAFile, 1<<20, false)
	if err != nil || !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return nil, errors.New("rack installation requires an enrollment CA")
	}
	var packageCA []byte
	if cfg.PackageCAFile != "" {
		packageCA, err = readBounded(cfg.PackageCAFile, 1<<20, false)
		if err != nil || !x509.NewCertPool().AppendCertsFromPEM(packageCA) {
			return nil, errors.New("invalid rack package CA")
		}
	}
	file, err := readBounded(cfg.CredentialKeyFile, 256, true)
	if err != nil {
		return nil, fmt.Errorf("load rack enrollment key: %w", err)
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(file)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("rack enrollment key must be 32 random bytes encoded as unpadded base64url")
	}
	portable := cfg
	portable.CredentialKeyFile, portable.EnrollmentCAFile, portable.PackageCAFile = "", "", ""
	data, _ := json.Marshal(portable)
	fingerprint := sha256.Sum256(fmt.Appendf(nil, "%s\n%x\n%x\n%x", data, sha256.Sum256(ca), sha256.Sum256(key), sha256.Sum256(packageCA)))
	return &Installation{Config: cfg, Image: IronicImage{Source: cfg.DebianImageURL, Algo: "sha256", SHA256: cfg.DebianImageSHA256, DownloadSource: "http"},
		Digest: hex.EncodeToString(fingerprint[:]), ca: ca, packageCA: packageCA, key: key}, nil
}

func validSHA256(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size && strings.ToLower(value) == value
}

func httpsArtifact(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.Path != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(value, " \r\n\t#")
}

// Credential derives the same secret after a controller restart. The
// regional database stores only the digest of the secret sent to the agent.
func (i *Installation) Credential(region, host, allocation string) (string, string) {
	mac := hmac.New(sha256.New, i.key)
	_, _ = fmt.Fprintf(mac, "ocean/rack-enrollment/v1\x00%s\x00%s\x00%s", region, host, allocation)
	token := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:])
}

type ConfigDrive struct {
	Metadata map[string]any `json:"meta_data"`
	Network  map[string]any `json:"network_data"`
	UserData string         `json:"user_data"`
}

func (i *Installation) Seed(asset Asset, allocation, fqdn, token string, address netip.Prefix, gateway netip.Addr, resolvers []netip.Addr) (ConfigDrive, error) {
	if !asset.valid() || !validUUID(allocation) || fqdn == "" || !address.Addr().Is4() || !address.Contains(gateway) || len(resolvers) == 0 {
		return ConfigDrive{}, errors.New("invalid rack first-boot configuration")
	}
	services := make([]map[string]string, 0, len(resolvers))
	for _, resolver := range resolvers {
		services = append(services, map[string]string{"type": "dns", "address": resolver.String()})
	}
	network := map[string]any{
		"links": []map[string]string{{"id": "management", "name": "mgmt0", "type": "phy", "ethernet_mac_address": asset.BootMAC}},
		"networks": []map[string]any{{"id": "management-ipv4", "type": "ipv4", "link": "management",
			"ip_address": address.Addr().String(), "netmask": net.IP(net.CIDRMask(address.Bits(), 32)).String(),
			"routes": []map[string]string{{"network": "0.0.0.0", "netmask": "0.0.0.0", "gateway": gateway.String()}}}},
		"services": services,
	}
	root := "/root/ocean-bootstrap/"
	files := make([]map[string]string, 0, 6)
	for _, item := range [][2]string{
		{"agent.json", enrollment.BootstrapAgentConfig(asset.HostID, i.Config.EnrollmentOrigin)},
		{"management-ca.pem", string(i.ca)}, {"enrollment.secret", token},
		{"package.url", i.Config.AgentPackageURL}, {"package.sha256", i.Config.AgentSHA256},
		{"install.sh", installRackAgent},
	} {
		files = append(files, map[string]string{"path": root + item[0], "content": item[1], "permissions": "0600"})
	}
	if len(i.packageCA) != 0 {
		files = append(files, map[string]string{"path": root + "package-ca.pem", "content": string(i.packageCA), "permissions": "0600"})
	}
	user, err := json.Marshal(map[string]any{"hostname": asset.HostID, "fqdn": fqdn, "ssh_pwauth": false,
		"write_files": files, "runcmd": [][]string{{"/bin/sh", root + "install.sh"}}})
	if err != nil {
		return ConfigDrive{}, err
	}
	return ConfigDrive{Metadata: map[string]any{"uuid": allocation, "hostname": fqdn, "meta": map[string]string{"dsmode": "local"}},
		Network: network, UserData: "#cloud-config\n" + string(user) + "\n"}, nil
}

const installRackAgent = `#!/bin/sh
set -eu
umask 077
export DEBIAN_FRONTEND=noninteractive
cd /root/ocean-bootstrap
if [ -f package-ca.pem ]; then
    set -- --cacert package-ca.pem
fi
curl --fail --silent --show-error --proto '=https' --max-time 180 "$@" --output ocean-agent.deb -- "$(cat package.url)"
printf '%s  ocean-agent.deb\n' "$(cat package.sha256)" | sha256sum --check --status -
rm -f -- package.url package.sha256 package-ca.pem
` + enrollment.InstallBootstrapAgent + `runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user start --no-block ocean-agent.service
` + enrollment.CleanBootstrapAgentFiles
