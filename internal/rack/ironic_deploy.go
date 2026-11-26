package rack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type IronicAllocation struct {
	ID    string `json:"uuid"`
	Node  string `json:"node_uuid"`
	State string `json:"state"`
}

func (i *Ironic) Allocation(ctx context.Context, id string) (*IronicAllocation, error) {
	if !validUUID(id) {
		return nil, errors.New("invalid Ironic allocation ID")
	}
	var allocation IronicAllocation
	if err := i.get(ctx, "/v1/allocations/"+id, &allocation); err != nil {
		var status managementStatus
		if errors.As(err, &status) && status.code == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	if allocation.ID != id {
		return nil, errors.New("Ironic returned another allocation")
	}
	return &allocation, nil
}

// Allocate restricts Ironic's atomic reservation to the verified asset.
func (i *Ironic) Allocate(ctx context.Context, id, node, resourceClass string) error {
	if !validUUID(id) || !validUUID(node) || resourceClass == "" {
		return errors.New("invalid Ironic allocation request")
	}
	return i.mutate(ctx, http.MethodPost, "/v1/allocations", "application/json", http.StatusCreated,
		map[string]any{"uuid": id, "resource_class": resourceClass, "candidate_nodes": []string{node}})
}

func (i *Ironic) SetImage(ctx context.Context, node string, image IronicImage) error {
	if !validUUID(node) {
		return errors.New("invalid Ironic node ID")
	}
	return i.mutate(ctx, http.MethodPatch, "/v1/nodes/"+node, "application/json", http.StatusOK,
		[]map[string]any{{"op": "replace", "path": "/instance_info", "value": image}})
}

func (i *Ironic) Transition(ctx context.Context, node, target string, seed *ConfigDrive) error {
	if !validUUID(node) || (target == "active") != (seed != nil) {
		return errors.New("invalid Ironic transition")
	}
	switch target {
	case "manage", "inspect", "provide", "active":
	default:
		return errors.New("unsupported Ironic transition")
	}
	return i.mutate(ctx, http.MethodPut, "/v1/nodes/"+node+"/states/provision", "application/json", http.StatusAccepted,
		struct {
			Target string       `json:"target"`
			Seed   *ConfigDrive `json:"configdrive,omitempty"`
		}{Target: target, Seed: seed})
}

func (i *Ironic) mutate(ctx context.Context, method, resource, contentType string, success int, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := i.request(ctx, method, resource, contentType, body)
	if err != nil {
		return err
	}
	response, err := i.client.Do(req)
	if err != nil {
		return fmt.Errorf("Ironic request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != success {
		return managementStatus{service: "Ironic", code: response.StatusCode}
	}
	return nil
}
