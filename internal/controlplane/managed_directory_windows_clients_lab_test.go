//go:build e2e

package controlplane

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/lab"
)

var windowsRecoveryProfiles = [2]string{"server-core", "windows-11"}

type windowsRecoveryProof struct {
	RecoveryID string    `json:"recoveryId"`
	Stage      string    `json:"stage"`
	Check      string    `json:"check"`
	Time       time.Time `json:"timestamp"`
	Machine    string    `json:"machine"`
	Edition    string    `json:"edition"`
	Controller string    `json:"controller"`
	DomainSID  string    `json:"domainSid"`
	Policy     string    `json:"policySha256"`
	PolicyACL  string    `json:"policyAcl,omitempty"`
	Secure     bool      `json:"secureChannel,omitempty"`
	Principal  string    `json:"principal,omitempty"`
	Group      string    `json:"group,omitempty"`
	Kerberos   bool      `json:"kerberos,omitempty"`
}

func verifyRegionalWindowsClients(t *testing.T, ctx context.Context, vm *lab.Lab, hosts windowsRecoveryHosts,
	run string, backup windowsRecoveryArchive, view windowsDirectoryView, status func() windowsDirectoryView) {
	t.Helper()
	var proof [2][3]windowsRecoveryProof
	start := time.Now().UTC()
	phase := func(stage string, controller identity.DirectoryControllerReadiness, after time.Time) {
		t.Helper()
		writeWindowsRecoveryResult(t, filepath.Join(hosts.state, "recovery-phase.json"), map[string]any{
			"recoveryId": run, "stage": stage, "controller": controller.DNSName, "address": controller.PrivateIPv4, "after": after,
		})
		t.Logf("Windows probe stage %s ready at %s. Submit records from both existing Windows guests.", stage, controller.DNSName)
	}
	valid := func(line windowsRecoveryProof, profile int, stage string, controller identity.DirectoryControllerReadiness, after time.Time) bool {
		edition := line.Edition == "ServerStandardEval" || line.Edition == "ServerStandard" ||
			line.Edition == "ServerDatacenter" || line.Edition == "ServerDatacenterEval"
		if profile == 1 {
			edition = line.Edition == "Professional" || line.Edition == "EnterpriseEval"
		}
		return line.RecoveryID == run && line.Stage == stage && line.Time.After(after) && line.Machine != "" && edition &&
			line.Controller == controller.DNSName && line.DomainSID == backup.Identity.SID && line.Policy == backup.Policy
	}
	phase("pair", view.Controllers[0], start)
	pollWindowsRecovery(t, ctx, "both guests to read the recovered directory and policy", func() bool {
		hosts.refresh(ctx, nil)
		for i, profile := range windowsRecoveryProfiles {
			for _, line := range readWindowsRecoveryProof(t, hosts.state, profile) {
				if valid(line, i, "pair", view.Controllers[0], start) && line.Check == "Machine" && line.Secure && line.PolicyACL != "" {
					proof[i][0] = line
				}
			}
		}
		return proof[0][0].Secure && proof[1][0].Secure
	})
	if err := vm.Stop(hosts.names[0]); err != nil {
		t.Fatal(err)
	}
	guests, err := vm.Status()
	if err != nil || guests[0].Running || !guests[1].Running {
		t.Fatalf("did not power off only the writer QEMU VM: %v", err)
	}
	stopped := time.Now().UTC()
	pollWindowsRecovery(t, ctx, "the region to observe the loss of the writer", func() bool {
		hosts.run(ctx, hosts.names[1], "touch /run/ocean-workload-network/.available", nil)
		current := status()
		return current.Availability == "Degraded" && len(current.Controllers) == 2 &&
			!current.Controllers[0].Ready && current.Controllers[1].Ready
	})
	phase("survivor", view.Controllers[1], stopped)
	pollWindowsRecovery(t, ctx, "both guests to verify machine trust, Kerberos sign-in and preserved policy on the survivor", func() bool {
		hosts.run(ctx, hosts.names[1], "touch /run/ocean-workload-network/.available", nil)
		for i, profile := range windowsRecoveryProfiles {
			for _, line := range readWindowsRecoveryProof(t, hosts.state, profile) {
				if !valid(line, i, "survivor", view.Controllers[1], stopped) || line.Machine != proof[i][0].Machine {
					continue
				}
				switch line.Check {
				case "Machine":
					if line.Secure && line.PolicyACL == proof[i][0].PolicyACL {
						proof[i][1] = line
					}
				case "Employee":
					if line.Kerberos && strings.EqualFold(line.Principal, "employee@"+backup.Identity.DNSName) &&
						strings.EqualFold(line.Group, backup.Identity.NetBIOSName+`\FileUsers`) {
						proof[i][2] = line
					}
				}
			}
		}
		return proof[0][1].Secure && proof[1][1].Secure && proof[0][2].Kerberos && proof[1][2].Kerberos
	})
	if proof[0][0].Machine == proof[1][0].Machine {
		t.Fatal("the Windows recovery scenario requires two distinct member machines")
	}
	writeWindowsRecoveryResult(t, filepath.Join(hosts.state, "evidence", "regional-windows-recovery.json"), map[string]any{
		"recoveryId": run, "directoryId": view.ID, "writerStoppedAt": stopped, "backupSha256": backup.Digest,
		"controllers": view.Controllers, "profiles": windowsRecoveryProfiles, "observations": proof,
	})
	t.Log("Both existing Windows guests verified the recovered pair, then retained machine trust, group membership, fresh Kerberos and policy through the surviving KVM controller.")
}

func writeWindowsRecoveryResult(t *testing.T, path string, data any) {
	t.Helper()
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pending", append(bytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".pending", path); err != nil {
		t.Fatal(err)
	}
}

func readWindowsRecoveryProof(t *testing.T, state, profile string) []windowsRecoveryProof {
	t.Helper()
	data, err := os.Open(filepath.Join(state, profile, "guest-serial.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	scan := bufio.NewScanner(data)
	var observations []windowsRecoveryProof
	for scan.Scan() {
		record, found := strings.CutPrefix(strings.TrimSpace(scan.Text()), "OCEAN-REGIONAL-RECOVERY ")
		if !found {
			continue
		}
		var line windowsRecoveryProof
		if json.Unmarshal([]byte(record), &line) == nil {
			observations = append(observations, line)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	return observations
}
