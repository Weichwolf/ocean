//go:build e2e

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func verifySMBLiveRevocation(t *testing.T, ctx context.Context, worker directoryKVMHosts, fixture, apiURL string, r *Region, share string) {
	t.Helper()
	const client, primary = "farm-1-node-02", "farm-1-node-01"
	const address = "10.232.1.14"
	const bound = 20 * time.Second
	marker := operationID()
	control := "/tmp/ocean-smb-revocation-" + marker

	script, err := os.ReadFile(filepath.Join(worker.root, "lab/verify_smb_revocation_client.sh"))
	if err != nil {
		t.Fatal(err)
	}
	quoted := "'" + strings.ReplaceAll(string(script), "'", "'\"'\"'") + "'"
	credential := filepath.Join(fixture, "smbwriter")
	info, err := os.Lstat(credential)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 128 {
		t.Fatalf("provide a private SMB writer fixture credential: %v", err)
	}
	password, err := os.ReadFile(credential)
	if err != nil {
		t.Fatal(err)
	}
	password = bytes.TrimSuffix(password, []byte{'\n'})
	if len(password) == 0 || bytes.ContainsAny(password, "\n\x00") {
		clear(password)
		t.Fatal("invalid SMB writer fixture credential")
	}
	type result struct {
		output []byte
		err    error
	}
	run, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan result, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer clear(password)
		input := io.MultiReader(bytes.NewReader(password), strings.NewReader("\n"))
		out, err := worker.ssh(run, client, "keyctl session - bash -c "+quoted+" -- "+address+" "+share+" "+marker, input)
		done <- result{out, err}
	}()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_, _ = worker.ssh(cleanup, client, "if test -d "+control+"; then touch "+control+"/abort; fi", nil)
		select {
		case <-finished:
			_, _ = worker.ssh(cleanup, client, "if test -d "+control+"; then find "+control+" -maxdepth 1 -type f -delete && rmdir "+control+"; fi", nil)
		case <-cleanup.Done():
			stop()
		}
	}()
	pollVMWorker(t, ctx, 30*time.Second, "the original CIFS descriptor and cached replica ticket", func() bool {
		select {
		case result := <-done:
			t.Fatalf("open the original Kerberos CIFS file: %v: %s", result.err, result.output)
		default:
		}
		probe, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		_, err := worker.ssh(probe, client, "test -f "+control+"/ready", nil)
		return err == nil
	})

	const partition = "ocean_smb_revocation_partition"
	partitionWorkerAPI(t, ctx, worker, apiURL, smbLabHost, partition)
	pollVMWorker(t, ctx, 40*time.Second, "SMB member management lease expiry", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", smbLabHost), clientv3.WithCountOnly())
		return err == nil && live.Count == 0
	})
	changedAt := time.Now()
	worker.run(ctx, primary, "sudo samba-tool group removemembers OceanShareWriters smbwriter", nil)
	add := "sudo samba-tool group addmembers OceanShareWriters smbwriter"
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		command := "sudo samba-tool group listmembers OceanShareWriters | grep -Fxq smbwriter || " + add
		if out, err := worker.ssh(cleanup, primary, command, nil); err != nil {
			t.Errorf("restore the SMB writer membership: %v: %s", err, out)
		}
	})
	worker.run(ctx, client, "touch "+control+"/check", nil)
	var measured time.Duration
	var oldHandle string
	timer := time.NewTimer(time.Until(changedAt.Add(bound)))
	defer timer.Stop()
	select {
	case observed := <-done:
		measured = time.Since(changedAt)
		if observed.err != nil || measured > bound || !bytes.Contains(observed.output, []byte("cachedTicketReconnect=ACCESS_DENIED")) {
			t.Fatalf("verify revocation within %s: %v: %s", bound, observed.err, observed.output)
		}
		for line := range strings.SplitSeq(string(observed.output), "\n") {
			if after, ok := strings.CutPrefix(line, "oldHandle="); ok {
				oldHandle = strings.TrimSpace(after)
			}
		}
		if oldHandle == "" {
			t.Fatalf("the previous CIFS handle did not produce an I/O result: %s", observed.output)
		}
	case <-timer.C:
		t.Fatalf("the old handle and cached-ticket reconnect were not blocked within %s", bound)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	checkClient := func(ctx context.Context, user, mode string) ([]byte, error) {
		probe := exec.CommandContext(ctx, "python3", "-B", "-c", `
import sys
from pathlib import Path
from verify_smb_member import private_password, probe_client
state, fixture, share, marker, user, mode = sys.argv[1:]
probe_client(Path(state), share, user, mode, "ocean-windows-" + marker + ".txt",
             private_password(Path(fixture) / user))
`, worker.state, fixture, share, marker, user, mode)
		probe.Dir = filepath.Join(worker.root, "lab")
		return probe.CombinedOutput()
	}
	if out, err := checkClient(ctx, "smbreader", "windows-reader"); err != nil {
		t.Fatalf("verify the unaffected reader and the acknowledged data: %v: %s", err, out)
	}
	worker.run(ctx, primary, add, nil)
	worker.run(ctx, smbLabHost, "sudo nft delete table inet "+partition, nil)
	pollVMWorker(t, ctx, 25*time.Second, "the SMB member management path to return", func() bool {
		live, err := r.client.Get(ctx, r.hostKey("live", smbLabHost), clientv3.WithCountOnly())
		return err == nil && live.Count == 1
	})
	pollVMWorker(t, ctx, bound, "the restored writer grant to allow a fresh session", func() bool {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := checkClient(probe, "smbwriter", "windows-read")
		return err == nil
	})
	evidence, err := json.MarshalIndent(map[string]any{"azureCLI": "2.93.0", "directoryWriter": "dc01.ad.ocean.test",
		"cachedTicketIssuer": "dc02.ad.ocean.test", "boundMilliseconds": bound.Milliseconds(),
		"revocationMilliseconds": measured.Milliseconds(), "oldHandle": oldHandle, "cachedTicketDenied": true,
		"readerKeptReadOnlyAccess": true, "managementLeaseWasExpired": true, "regrantedWriterReadVerified": true}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(worker.state, "evidence")
	if err := os.MkdirAll(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destination, "kerberos-smb-revocation.json"), append(evidence, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("the old SMB handle (%s) and a cached service-ticket reconnect were denied in %s", oldHandle, measured.Round(time.Millisecond))
}
