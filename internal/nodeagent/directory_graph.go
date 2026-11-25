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

func (j *joinClient) runDirectoryGraphTask(ctx context.Context, name string, assignment enrollment.Assignment) error {
	path := j.url() + "/directories/" + assignment.TenantID + "/" + assignment.Generation + "/graph-task"
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
		return fmt.Errorf("directory Graph task returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(data)
	var task enrollment.DirectoryGraphTask
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &task) != nil ||
		!task.Valid() || !enrollment.ValidDirectoryJoinID(task.ID) {
		return errors.New("invalid directory Graph task")
	}
	if time.Now().Unix() >= task.ExpiresAt {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, 7*time.Second)
	command := localPodman(probe, "exec", "-i", name, "/usr/bin/timeout", "6", "/usr/bin/python3", directoryControllerPath, "graph")
	command.Stdin = bytes.NewReader(data)
	output, err := command.Output()
	cancel()
	if err != nil {
		return errors.New("directory Graph operation will retry")
	}
	result := enrollment.DirectoryGraphResult{ID: task.ID}
	if len(output) > enrollment.MaxDirectoryGraphResult || json.Unmarshal(output, &result) != nil || result.ID != task.ID || !result.Valid(task.Operation) {
		return errors.New("invalid directory Graph receipt")
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
	defer func() { _ = ack.Body.Close() }()
	if ack.StatusCode != http.StatusNoContent {
		return fmt.Errorf("directory Graph acknowledgement returned HTTP %d", ack.StatusCode)
	}
	return nil
}
