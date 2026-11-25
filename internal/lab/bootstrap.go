package lab

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/Weichwolf/ocean/internal/config"
)

type bootstrapManifest struct {
	HostID      string `json:"hostId"`
	Origin      string `json:"origin"`
	CAFile      string `json:"caFile"`
	TokenFile   string `json:"tokenFile"`
	PackageFile string `json:"packageFile"`
}

type bootstrapSeed struct {
	host        string
	digest      string
	files       []any
	packageData []byte
}

func loadBootstrapSeed(manifestPath string, guests map[string]Guest) (*bootstrapSeed, error) {
	manifest, err := config.Load(manifestPath, bootstrapManifest{})
	if err != nil {
		return nil, err
	}
	guest, exists := guests[manifest.HostID]
	if !exists || !slices.Contains(guest.Roles, "compute") || !slices.ContainsFunc(guest.Interfaces, func(i Interface) bool { return i.Name == "mgmt0" }) {
		return nil, errors.New("enrollment requires a planned compute guest with a management interface")
	}
	origin, err := url.Parse(manifest.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("the enrollment origin must be an HTTPS origin")
	}
	token, err := os.Open(manifest.TokenFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = token.Close() }()
	info, err := token.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("the enrollment token must be a private regular file")
	}
	secret, err := io.ReadAll(io.LimitReader(token, 128))
	if err != nil {
		return nil, err
	}
	credential := strings.TrimSpace(string(secret))
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(raw) != 32 || info.Size() >= 128 {
		return nil, errors.New("invalid host bootstrap token")
	}
	ca, err := os.ReadFile(manifest.CAFile)
	if err != nil {
		return nil, err
	}
	if !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return nil, errors.New("the management CA must contain a PEM certificate")
	}
	packageFile, err := os.Open(manifest.PackageFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = packageFile.Close() }()
	packageData, err := io.ReadAll(io.LimitReader(packageFile, 32<<20))
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(packageData[:min(len(packageData), 8)]), "!<arch>\n") || len(packageData) == 32<<20 {
		return nil, errors.New("the lab seed requires a Debian package smaller than 32 MiB")
	}
	agentConfig, _ := json.Marshal(map[string]any{
		"listenAddress": "127.0.0.1:8081",
		"enrollment": map[string]string{"origin": manifest.Origin, "hostId": manifest.HostID, "managementInterface": "mgmt0",
			"caFile": "/etc/ocean-agent/management-ca.pem", "tokenFile": "/etc/ocean-agent/enrollment.secret",
			"stateDirectory": "/var/lib/ocean-agent/host-enrollment"},
	})
	hash := sha256.New()
	for _, data := range [][]byte{agentConfig, ca, []byte(credential), packageData, []byte(provisionAgent)} {
		digest := sha256.Sum256(data)
		hash.Write(digest[:])
	}
	prefix := "/root/ocean-bootstrap/"
	return &bootstrapSeed{host: manifest.HostID, digest: hex.EncodeToString(hash.Sum(nil)), packageData: packageData, files: []any{
		seedFile(prefix+"agent.json", string(agentConfig), "text/plain"),
		seedFile(prefix+"management-ca.pem", string(ca), "text/plain"),
		seedFile(prefix+"enrollment.secret", credential, "text/plain"),
		seedFile(prefix+"provision.sh", provisionAgent, "text/plain"),
	}}, nil
}

func seedFile(path, content, encoding string) map[string]string {
	return map[string]string{"path": path, "content": content, "encoding": encoding, "permissions": "0600"}
}

const provisionAgent = `#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
cd /root/ocean-bootstrap
mountpoint=/run/ocean-bootstrap-seed
mkdir -m 0700 "$mountpoint"
mount -t iso9660 -o ro /dev/disk/by-label/cidata "$mountpoint"
trap 'umount "$mountpoint"' EXIT
install -m 0600 "$mountpoint/ocean-agent.deb" ocean-agent.deb
umount "$mountpoint"
trap - EXIT
rmdir "$mountpoint"
apt-get -q update
OCEAN_AGENT_DEFER_START=1 apt-get -yq --no-install-recommends install /root/ocean-bootstrap/ocean-agent.deb
install -m 0644 agent.json /etc/ocean-agent/config.json
install -m 0644 management-ca.pem /etc/ocean-agent/management-ca.pem
install -m 0600 -o ocean-agent -g ocean-agent enrollment.secret /etc/ocean-agent/enrollment.secret
uid=$(id -u ocean-agent)
loginctl enable-linger ocean-agent
systemctl start "user@$uid.service"
runuser -u ocean-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" systemctl --user start ocean-agent.service
rm -f -- ocean-agent.deb agent.json management-ca.pem enrollment.secret
`
