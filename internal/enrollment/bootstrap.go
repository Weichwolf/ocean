package enrollment

import "encoding/json"

// BootstrapAgentConfig is shared by the NoCloud and ConfigDrive installers.
func BootstrapAgentConfig(host, origin string) string {
	value, _ := json.Marshal(map[string]any{
		"listenAddress": "127.0.0.1:8081",
		"enrollment": map[string]string{"origin": origin, "hostId": host, "managementInterface": "mgmt0",
			"caFile": "/etc/ocean-agent/management-ca.pem", "tokenFile": "/etc/ocean-agent/enrollment.secret",
			"stateDirectory": "/var/lib/ocean-agent/host-enrollment"},
	})
	return string(value)
}

// InstallBootstrapAgent expects the verified package and protected seed files
// in the script's working directory.
const InstallBootstrapAgent = `apt-get -q update
OCEAN_AGENT_DEFER_START=1 apt-get -yq --no-install-recommends install /root/ocean-bootstrap/ocean-agent.deb
install -m 0644 agent.json /etc/ocean-agent/config.json
install -m 0644 management-ca.pem /etc/ocean-agent/management-ca.pem
install -m 0600 -o ocean-agent -g ocean-agent enrollment.secret /etc/ocean-agent/enrollment.secret
uid=$(id -u ocean-agent)
loginctl enable-linger ocean-agent
systemctl start "user@$uid.service"
`

const CleanBootstrapAgentFiles = "rm -f -- ocean-agent.deb agent.json management-ca.pem enrollment.secret\n"
