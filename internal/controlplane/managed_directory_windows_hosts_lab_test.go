//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/lab"
)

type directoryKVMHosts struct {
	root, state, directory string
	names                  [2]string
	t                      *testing.T
}

func (f directoryKVMHosts) ssh(ctx context.Context, host, command string, input io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(f.root, "bin/ocean-lab"), "ssh", "-state", f.state, host, "--", command)
	cmd.Stdin = input
	return cmd.CombinedOutput()
}

func (f directoryKVMHosts) run(ctx context.Context, host, command string, input io.Reader) {
	f.t.Helper()
	out, err := f.ssh(ctx, host, command, input)
	if err != nil {
		f.t.Fatalf("lab host %s: %v: %s", host, err, out)
	}
}

func (f directoryKVMHosts) path(file string) string {
	return "/home/ocean/" + f.directory + "/" + file
}

func (f *directoryKVMHosts) approve(ctx context.Context, region *Region, guests []lab.GuestStatus) [2]string {
	f.t.Helper()
	var inventory []enrollment.Approval
	var tokens [2]string
	for i, status := range guests {
		host := status.Guest.Name
		if host != fmt.Sprintf("farm-1-node-%02d", i+1) {
			f.t.Fatal("the two isolated directory hosts must be farm-1-node-01 and farm-1-node-02")
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			f.t.Fatal(err)
		}
		f.names[i], tokens[i] = host, base64.RawURLEncoding.EncodeToString(entropy[:])
		for _, device := range status.Guest.Interfaces {
			if device.Name != "mgmt0" {
				continue
			}
			inventory = append(inventory, enrollment.Approval{HostID: host, MAC: device.MAC, Address: device.Address.Addr().String(),
				Profile: "debian-13", Cell: region.cell, Pool: "approved", Roles: []string{"compute"},
				MinimumCPU: 1, MinimumMemoryMiB: 832, TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(tokens[i]))),
				ExpiresAt: time.Now().Add(time.Hour).UTC()})
		}
	}
	if len(inventory) != 2 {
		f.t.Fatal("both directory guests require a management NIC")
	}
	if err := region.seedHostInventory(ctx, inventory); err != nil {
		f.t.Fatal(err)
	}
	return tokens
}

func (f *directoryKVMHosts) startAgents(ctx context.Context, region *Region, guests []lab.GuestStatus, origin, image string, ca []byte) {
	f.t.Helper()
	tokens := f.approve(ctx, region, guests)
	for i, host := range f.names {
		f.run(ctx, host, "set -eu; umask 077; mkdir "+f.path("")+
			"; ! podman ps --quiet --filter label=ocean.directory-controller | grep -q ."+
			"; podman image exists "+image+
			"; sudo install -d -o ocean -g ocean -m 0755 /run/ocean-workload-network", nil)
		conf, _ := json.Marshal(map[string]any{"listenAddress": "127.0.0.1:19081", "enrollment": map[string]any{
			"origin": origin, "hostId": host, "managementInterface": "mgmt0", "caFile": f.path("ca.pem"),
			"tokenFile": f.path("join-token"), "stateDirectory": f.path("state"), "directoryImage": image,
		}})
		for name, contents := range map[string][]byte{"agent.json": conf, "ca.pem": ca, "join-token": []byte(tokens[i])} {
			f.run(ctx, host, "umask 077; cat >"+f.path(name), bytes.NewReader(contents))
		}
		binary, err := os.Open(filepath.Join(f.root, "bin/ocean-agent"))
		if err != nil {
			f.t.Fatal(err)
		}
		f.run(ctx, host, "umask 077; cat >"+f.path("ocean-agent")+" && chmod 0700 "+f.path("ocean-agent"), binary)
		if err := binary.Close(); err != nil {
			f.t.Fatal(err)
		}
		f.run(ctx, host, "touch /run/ocean-workload-network/.available; nohup nice -n 10 "+f.path("ocean-agent")+
			" -config "+f.path("agent.json")+" >"+f.path("agent.log")+" 2>&1 < /dev/null & echo $! >"+f.path("agent.pid"), nil)
	}
}

func (f directoryKVMHosts) refresh(ctx context.Context, addresses []string) {
	f.t.Helper()
	for i, host := range f.names {
		script := "set -eu; kill -0 $(cat " + f.path("agent.pid") + ") 2>/dev/null || { tail -15 " +
			f.path("agent.log") + "; exit 1; }; touch /run/ocean-workload-network/.available"
		if addresses != nil {
			// QEMU VDE supplies a dedicated workload NIC on each disposable
			// Debian host. The fixture attaches it to the agent's namespace.
			// The restore worker keeps its original networkless namespace.
			script += `; name=$(podman ps --filter label=ocean.directory-controller --format '{{.Names}}'); test -n "$name" || exit 0
pid=$(podman inspect --format '{{.State.Pid}}' "$name")
case "$pid" in ''|*[!0-9]*|0|1) exit 0;; esac
if ! sudo nsenter -t "$pid" -n ip link show dev work0 >/dev/null 2>&1; then
    sudo ip link set dev work0 netns "$pid"
    sudo nsenter -t "$pid" -n ip link set dev work0 up
fi
sudo nsenter -t "$pid" -n ip address replace ` + addresses[i] + " dev work0"
		}
		f.run(ctx, host, script, nil)
	}
}

func (f directoryKVMHosts) stageArchive(ctx context.Context, host, id, archive string) {
	f.t.Helper()
	data, err := os.Open(archive)
	if err != nil {
		f.t.Fatal(err)
	}
	defer data.Close()
	directory := f.path("state/directory-recovery")
	target := directory + "/" + id + ".tar"
	f.run(ctx, host, "set -eu; umask 077; mkdir -p "+directory+"; cat >"+target+".pending; mv "+target+".pending "+target, data)
}

func (f directoryKVMHosts) removeStagedArchive(ctx context.Context, host, id string) {
	f.t.Helper()
	f.run(ctx, host, "rm -f "+f.path("state/directory-recovery/"+id+".tar"), nil)
}

func (f directoryKVMHosts) shutdownAgents(ctx context.Context) {
	for _, host := range f.names {
		if host == "" {
			continue
		}
		if f.t.Failed() {
			out, _ := f.ssh(ctx, host, "tail -15 "+f.path("agent.log"), nil)
			f.t.Logf("agent on %s: %s", host, out)
		}
		_, _ = f.ssh(ctx, host, "if test -f "+f.path("agent.pid")+"; then kill -- $(cat "+f.path("agent.pid")+
			") 2>/dev/null || true; "+
			"for label in ocean.directory-controller ocean.directory-restore; do "+
			"for c in $(podman ps --filter label=$label --quiet); do nice -n 10 podman stop --time 3 \"$c\"; done; done; "+
			"fi; rm -f -- "+f.path("join-token")+" "+f.path("state/identity.key")+
			"; if test -d "+f.path("state/directory-recovery")+"; then rm -f -- "+f.path("state/directory-recovery/")+
			"*.tar "+f.path("state/directory-recovery/")+"*.tar.pending; fi", nil)
	}
}
