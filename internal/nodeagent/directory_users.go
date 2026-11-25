package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

func (j *joinClient) runDirectoryUserTask(ctx context.Context, name string, assignment enrollment.Assignment) error {
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/user-task"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("directory user task returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(data)
	var task enrollment.DirectoryUserTask
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &task) != nil ||
		!task.Valid() || !enrollment.ValidDirectoryJoinID(task.ID) {
		return errors.New("invalid directory user task")
	}
	if time.Now().Unix() >= task.ExpiresAt {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 7*time.Second)
	command := localPodman(probe, "exec", "-i", name, "/usr/bin/timeout", "6", "/usr/bin/python3", directoryControllerPath, "graph-users")
	command.Stdin = bytes.NewReader(data)
	output, err := command.Output()
	cancel()
	if err != nil {
		return errors.New("directory user operation will retry")
	}
	result := enrollment.DirectoryUserResult{ID: task.ID}
	if len(output) > enrollment.MaxDirectoryUserResult || json.Unmarshal(output, &result) != nil || result.ID != task.ID || !result.Valid(task.Operation) {
		return errors.New("invalid directory user receipt")
	}
	payload, _ := json.Marshal(result)
	defer clear(payload)
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	ack, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer ack.Body.Close()
	if ack.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory user acknowledgement returned HTTP %d", ack.StatusCode)
	}
	return nil
}
