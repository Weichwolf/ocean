package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
)

func validVMTask(t workload.VMTask) bool {
	if !vmIDPattern.MatchString(t.MachineID) || !vmIDPattern.MatchString(t.Generation) || !vmIDPattern.MatchString(t.Revision) ||
		!taskIdentityPattern.MatchString(t.TenantID) || !taskIdentityPattern.MatchString(t.SubscriptionID) || !taskIdentityPattern.MatchString(t.ID) ||
		!t.Disk.Valid() || t.Disk.ID != "vm-"+t.MachineID {
		return false
	}
	if _, ok := workload.VirtualMachineSize(t.Size); !ok {
		return false
	}
	switch t.State {
	case workload.Running:
		return len(t.VolumeKey) == storage.KeySize && t.Network != nil && t.Network.ValidFor(t.Network.Address.Addr()) && t.Network.Address.Addr().IsPrivate()
	case workload.Stopped, workload.Removed:
		return len(t.VolumeKey) == 0 && t.Network == nil
	default:
		return false
	}
}

func (j *joinClient) vmTasks(ctx context.Context) ([]workload.VMTask, error) {
	var tasks []workload.VMTask
	seen := make(map[string]bool)
	cursor := ""
	for range 512 {
		page, err := j.vmTaskPage(ctx, cursor)
		if err == nil && len(page.Tasks) <= 8 && (page.Next == "" || page.Next > cursor) {
			for _, task := range page.Tasks {
				if !validVMTask(task) || seen[task.MachineID] || len(tasks) >= 4096 {
					err = errors.New("invalid VM assignment page")
					break
				}
				seen[task.MachineID] = true
				tasks = append(tasks, task)
			}
		} else if err == nil {
			err = errors.New("invalid VM assignment pagination")
		}
		if err != nil {
			for _, task := range tasks {
				clear(task.VolumeKey)
			}
			for _, task := range page.Tasks {
				clear(task.VolumeKey)
			}
			return nil, err
		}
		if page.Next == "" {
			return tasks, nil
		}
		cursor = page.Next
	}
	for _, task := range tasks {
		clear(task.VolumeKey)
	}
	return nil, errors.New("VM assignments exceed the page limit")
}

func (j *joinClient) vmTaskPage(ctx context.Context, cursor string) (workload.VMTaskPage, error) {
	var page workload.VMTaskPage
	path := j.url() + "/vm-tasks"
	if cursor != "" {
		path += "?continuation=" + url.QueryEscape(cursor)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return page, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return page, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return page, fmt.Errorf("VM task request returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&page); err != nil || decoder.Decode(new(any)) != io.EOF {
		return page, errors.New("invalid VM task response")
	}
	if strings.ContainsAny(page.Next, " \t\r\n") {
		return page, errors.New("invalid VM task cursor")
	}
	return page, nil
}

func (j *joinClient) reportVM(ctx context.Context, task workload.VMTask, state string) error {
	report := workload.VMReport{AssignmentID: task.AssignmentID, State: state, DiskReleased: state == workload.Removed}
	body, _ := json.Marshal(report)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, j.url()+"/vm-tasks/status", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := j.client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusConflict {
		return fmt.Errorf("VM status report returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (j *joinClient) confirmVMTask(ctx context.Context, wanted workload.VMTask) error {
	tasks, err := j.vmTasks(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, task := range tasks {
		clear(task.VolumeKey)
		if task.AssignmentID == wanted.AssignmentID && task.MachineID == wanted.MachineID && task.State == wanted.State && task.Disk == wanted.Disk {
			found = true
		}
	}
	if !found {
		return errors.New("the regional VM assignment changed before the operation")
	}
	return nil
}
