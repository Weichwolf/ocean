package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

func (j *joinClient) runDirectoryJoinTask(ctx context.Context, name string, assignment enrollment.Assignment) error {
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/join-task"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("directory join task returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	defer clear(data)
	var task enrollment.DirectoryJoinTask
	if err != nil || len(data) > 2048 || json.Unmarshal(data, &task) != nil || !task.Valid() {
		return errors.New("invalid directory join task")
	}
	if time.Now().Unix() >= task.Input.ExpiresAt {
		return nil
	}
	succeeded, err := executeDirectoryJoin(ctx, name, assignment.Directory.DNSName, task)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(enrollment.DirectoryJoinResult{Attempt: task.Attempt, Succeeded: &succeeded})
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	ack, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = ack.Body.Close() }()
	if ack.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory join acknowledgement returned HTTP %d", ack.StatusCode)
	}
	return nil
}

func executeDirectoryJoin(ctx context.Context, name, domain string, task enrollment.DirectoryJoinTask) (bool, error) {
	payload, _ := json.Marshal(task.Input)
	defer clear(payload)
	probe, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	command := localPodman(probe, "exec", "-i", name, "/usr/bin/timeout", "6", "/usr/bin/python3", directoryControllerPath, task.Command)
	command.Stdin = bytes.NewReader(payload)
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 3 {
			return false, nil
		}
		return false, errors.New("directory join operation will retry")
	}
	var receipt struct {
		UPN     string `json:"userPrincipalName"`
		Machine string `json:"machineName"`
		Expiry  int64  `json:"expiresAt"`
	}
	if json.Unmarshal(output, &receipt) != nil || receipt.UPN != task.Input.Username()+"@"+domain ||
		receipt.Machine != task.Input.Machine || receipt.Expiry != task.Input.ExpiresAt {
		return false, errors.New("invalid directory join receipt")
	}
	return true, nil
}
