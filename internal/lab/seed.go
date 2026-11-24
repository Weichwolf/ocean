package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func bootstrapMAC(guest Guest) string {
	return strings.Replace(guest.Interfaces[0].MAC, "02:4f:00:", "02:4f:01:", 1)
}

func (lab *Lab) seed(ctx context.Context, guest Guest) error {
	directory := lab.node(guest.Name)
	publicKey, err := os.ReadFile(filepath.Join(lab.root, "ssh-key.pub"))
	if err != nil {
		return err
	}
	interfaces := map[string]any{
		"boot0": map[string]any{
			"match":    map[string]string{"macaddress": bootstrapMAC(guest)},
			"set-name": "boot0",
			"dhcp4":    true,
		},
	}
	hosts := fmt.Sprintf("127.0.0.1 localhost\n127.0.1.1 %s\n::1 localhost ip6-localhost ip6-loopback\n", guest.Name)
	for _, attachment := range guest.Interfaces {
		interfaces[attachment.Name] = map[string]any{
			"match":     map[string]string{"macaddress": attachment.MAC},
			"set-name":  attachment.Name,
			"addresses": []string{attachment.Address.String()},
		}
		if attachment.Name == "mgmt0" {
			hosts += fmt.Sprintf("10.231.%d.10 arm.farm-%d.ocean.test id.farm-%d.ocean.test\n", guest.Farm, guest.Farm, guest.Farm)
		}
	}
	files := []struct {
		name, prefix string
		data         any
	}{
		{"user-data", "#cloud-config\n", map[string]any{
			"ssh_pwauth": false,
			"users": []any{map[string]any{
				"name": "ocean", "shell": "/bin/bash", "sudo": "ALL=(ALL) NOPASSWD:ALL",
				"ssh_authorized_keys": []string{strings.TrimSpace(string(publicKey))},
			}},
			"write_files": []any{map[string]any{"path": "/etc/hosts", "content": hosts}},
		}},
		{"meta-data", "", map[string]string{"instance-id": guest.Name, "local-hostname": guest.Name}},
		{"network-config", "", map[string]any{"version": 2, "ethernets": interfaces}},
	}
	for _, file := range files {
		encoded, err := json.Marshal(file.data)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, file.name), append([]byte(file.prefix), encoded...), 0o600); err != nil {
			return err
		}
	}
	return command(ctx, "cloud-localds", "--network-config", filepath.Join(directory, "network-config"),
		filepath.Join(directory, "seed.iso"), filepath.Join(directory, "user-data"), filepath.Join(directory, "meta-data"))
}
