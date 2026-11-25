package nodeagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

func functionPaths(volume string) (string, string) {
	root := filepath.Join(workloadMountRoot, volume)
	return filepath.Join(root, "secrets"), filepath.Join(root, "host-storage")
}

func prepareFunctionStorage(task workload.Task) error {
	runtime := task.Function
	if !storage.ValidID(task.VolumeID) || !storage.ValidAccount(runtime.Account) || !functions.ValidKey(runtime.MasterKey) {
		return errors.New("invalid Function host storage assignment")
	}
	storageKey, err := base64.StdEncoding.DecodeString(runtime.StorageKey)
	clear(storageKey)
	if err != nil || len(storageKey) != 64 {
		return errors.New("invalid Function host storage credential")
	}
	secrets, data := functionPaths(task.VolumeID)
	for _, path := range []string{secrets, data} {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("cannot initialize the Function host directory")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return errors.New("Function host directory is not private")
		}
	}
	host := filepath.Join(secrets, "host.json")
	if info, err := os.Lstat(host); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("Function host credential is not private")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect the Function host credential")
	}
	key, _ := json.Marshal(map[string]any{
		"masterKey":    map[string]any{"name": "_master", "value": runtime.MasterKey, "encrypted": false},
		"functionKeys": []any{}, "systemKeys": []any{},
	})
	if err := publishFile(host, key); err != nil {
		return errors.New("cannot seed the Function host credential")
	}
	return nil
}

func (j *joinClient) ensureFunctionSidecar(ctx context.Context, name string, task workload.Task) error {
	sidecar := name + "-storage"
	process, exists, err := inspectContainer(ctx, sidecar, localPodman)
	if err != nil || process.Running {
		return err
	}
	if exists {
		return podmanAction(ctx, "start", sidecar)
	}
	file, err := os.CreateTemp(j.config.StateDirectory, ".function-storage-env-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := fmt.Fprintf(file, "AZURITE_ACCOUNTS=%s:%s\nNODE_OPTIONS=--max-old-space-size=40\n", task.Function.Account, task.Function.StorageKey); err != nil {
		return errors.Join(errors.New("cannot configure the Function host storage service"), file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, data := functionPaths(task.VolumeID)
	return podmanAction(ctx, "run", "--detach", "--pull=missing", "--name", sidecar, "--network=container:"+name,
		"--cpus", "0.20", "--memory", "88m", "--memory-swap", "88m", "--pids-limit", "64", "--restart", "always",
		"--security-opt=no-new-privileges", "--cap-drop=ALL", "--log-driver=k8s-file", "--log-opt=max-size=64kb",
		"--env-file", file.Name(), "--mount", "type=bind,source="+data+",target=/data",
		"--", functions.HostStorageImage, "azurite", "--silent", "--location", "/data", "--blobHost", "127.0.0.1",
		"--queueHost", "127.0.0.1", "--tableHost", "127.0.0.1", "--skipApiVersionCheck")
}

func (j *joinClient) functionContainerConfig(name string) string {
	return filepath.Join(j.config.StateDirectory, name+".function")
}

func (j *joinClient) removeFunctionSidecars(ctx context.Context, name string) error {
	return podmanAction(ctx, "rm", "--force", "--ignore", "--time", "1", name+"-telemetry", name+"-storage")
}

func functionAdmin(ctx context.Context, name string, runtime functions.Runtime, request functions.AdminRequest) (functions.AdminResult, error) {
	output := functions.AdminResult{ID: request.ID}
	endpoint := "/admin/functions"
	var mutation []byte
	if request.Function != "" {
		if !functions.ValidFunctionName(request.Function) {
			return output, errors.New("invalid native Function name")
		}
		endpoint += "/" + request.Function + "/keys"
	}
	if request.Name != "" {
		if request.Function == "" || !functions.ValidFunctionName(request.Name) || !functions.ValidKey(request.Value) {
			return output, errors.New("invalid native Function key")
		}
		endpoint += "/" + request.Name
		mutation, _ = json.Marshal(map[string]string{"name": request.Name, "value": request.Value})
	}
	if !functions.ValidKey(runtime.MasterKey) {
		return output, errors.New("invalid native Function master key")
	}
	deadline, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	args := []string{"exec", "--interactive", name, "/usr/bin/curl", "--disable", "--silent", "--noproxy", "*", "--max-time", "3",
		"--proto", "=http", "--max-filesize", "49152", "--config", "-", "--write-out", "\n%{http_code}",
		"http://127.0.0.1:80" + endpoint}
	var input bytes.Buffer
	fmt.Fprintf(&input, "header = %s\n", strconv.Quote("x-functions-key: "+runtime.MasterKey))
	if len(mutation) != 0 {
		input.WriteString("request = \"PUT\"\nheader = \"content-type: application/json\"\n")
		fmt.Fprintf(&input, "data-binary = %s\n", strconv.Quote(string(mutation)))
	}
	command := localPodman(deadline, args...)
	command.Stdin = &input
	stream, err := command.StdoutPipe()
	if err != nil {
		return output, errors.New("cannot query the Function host")
	}
	if err := command.Start(); err != nil {
		return output, errors.New("cannot query the Function host")
	}
	const limit = 48 << 10
	response, readErr := io.ReadAll(io.LimitReader(stream, limit+1))
	if len(response) > limit || readErr != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if waitErr != nil || readErr != nil || len(response) > limit {
		return output, errors.New("the native Function host did not answer")
	}
	index := bytes.LastIndexByte(response, '\n')
	if index == -1 {
		return output, errors.New("invalid Function host response")
	}
	output.Status, err = strconv.Atoi(strings.TrimSpace(string(response[index+1:])))
	if err != nil || output.Status < 100 || output.Status > 599 {
		return output, errors.New("invalid Function host response status")
	}
	output.Body = response[:index]
	return output, nil
}
