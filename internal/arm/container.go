package arm

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/workload"
)

var (
	ErrContainerMissing            = errors.New("the container group does not exist")
	ErrContainerBusy               = errors.New("a different container group operation is in progress")
	ErrContainerChanged            = errors.New("updates to the container group configuration are unsupported")
	ErrContainerQuota              = errors.New("the subscription has insufficient workload capacity")
	ErrContainerCapacity           = errors.New("no eligible host has sufficient workload capacity")
	ErrContainerDelegationRequired = errors.New("the subnet requires the Container Instance delegation")
	ErrContainerNetworkConflict    = errors.New("the region is already routing an overlapping private workload network")
)

type ContainerGroupStore interface {
	CreateContainerGroup(context.Context, SubscriptionScope, string, ResourceAddress, workload.ContainerGroup) (InventoryResource, *Operation, bool, error)
	MutateContainerGroup(context.Context, SubscriptionScope, string, ResourceAddress, string) (*Operation, error)
	ContainerLogs(context.Context, SubscriptionScope, ResourceAddress, string, int) (string, error)
}

func containerRoute(group string, path []string) (armRoute, bool) {
	if len(path) < 2 || !strings.EqualFold(strings.Join(path[:2], "/"), workload.ContainerGroupType) {
		return armRoute{}, false
	}
	return armRoute{collection: "containerGroup", group: group, name: strings.Join(path[2:], "/")}, true
}

func (s Server) containerGroup(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, path string) {
	if s.Containers == nil {
		unavailable(w)
		return
	}
	if path == "" {
		s.listContainerGroups(ctx, w, r, scope, reader, group)
		return
	}
	parts := strings.Split(path, "/")
	name := parts[0]
	if group == "" || !workload.ValidName(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The container group identifier is invalid.")
		return
	}
	address := ResourceAddress{Group: group, Path: workload.ContainerGroupType + "/" + name}
	if len(parts) == 4 && strings.EqualFold(parts[1], "containers") && strings.EqualFold(parts[3], "logs") {
		s.containerLogs(ctx, w, r, scope, reader, address, parts[2])
		return
	}
	if _, ok := readQuery(w, r, workload.ContainerGroupAPIVersion, nil); !ok {
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		action := strings.ToLower(parts[1])
		if action == "start" || action == "stop" || action == "restart" {
			s.containerAction(ctx, w, scope, actor, address, action)
			return
		}
	}
	if len(parts) != 1 {
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The container group operation is unsupported.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if resource == nil {
			containerError(w, ErrContainerMissing)
		} else {
			writeJSON(w, http.StatusOK, resource.view(scope))
		}
	case http.MethodPut:
		var input workload.ContainerGroup
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 96<<10), &input); err != nil ||
			input.Location != s.Location || !validTags(input.Tags) || input.Validate(name) != nil {
			containerError(w, workload.ErrInvalidContainer)
			return
		}
		if len(input.Properties.SubnetIDs) != 0 {
			parent, _, ok := SubnetParent(scope, input.Properties.SubnetIDs[0].ID)
			if !ok || !strings.EqualFold(parent.Group, group) {
				containerError(w, workload.ErrInvalidContainer)
				return
			}
		}
		resource, operation, created, err := s.Containers.CreateContainerGroup(ctx, scope, actor, address, input)
		if err != nil {
			containerError(w, err)
			return
		}
		if operation != nil && operation.Status == OperationInProgress {
			s.setContainerOperation(w, scope, *operation, address)
		}
		writeJSON(w, createdStatus(created), resource.view(scope))
	case http.MethodDelete:
		s.containerAction(ctx, w, scope, actor, address, "delete")
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) setContainerOperation(w http.ResponseWriter, scope SubscriptionScope, operation Operation, address ResourceAddress) {
	w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+"?api-version="+resourceAPIVersion)
	w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+workload.ContainerGroupAPIVersion)
	w.Header().Set("Retry-After", "1")
}

func (s Server) containerAction(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, actor string, address ResourceAddress, action string) {
	operation, err := s.Containers.MutateContainerGroup(ctx, scope, actor, address, action)
	if err != nil {
		containerError(w, err)
		return
	}
	if operation == nil || operation.Status == OperationSucceeded {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch action {
	case "stop":
		// The pinned stop command has no poller. Only return 204 when the
		// assigned agent has confirmed that the container has stopped.
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for operation != nil && operation.Status == OperationInProgress {
			select {
			case <-ctx.Done():
				unavailable(w)
				return
			case <-ticker.C:
				operation, err = s.Operations.GetOperation(ctx, scope, operation.ID)
				if err != nil {
					unavailable(w)
					return
				}
			}
		}
		if operation == nil || operation.Status != OperationSucceeded {
			containerError(w, ErrContainerBusy)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "delete":
		s.acceptOperation(w, scope, *operation)
	case "restart":
		s.setContainerOperation(w, scope, *operation, address)
		w.WriteHeader(http.StatusNoContent)
	default:
		s.setContainerOperation(w, scope, *operation, address)
		w.WriteHeader(http.StatusAccepted)
	}
}

func (s Server) listContainerGroups(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader, group string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	query, ok := readQuery(w, r, workload.ContainerGroupAPIVersion, func(key, value string) bool {
		return key == "$skiptoken" && value != ""
	})
	if !ok {
		return
	}
	search, ok := inventoryQuery(query, group)
	if !ok {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The container group continuation is invalid.")
		return
	}
	search.Type = workload.ContainerGroupType
	resources, err := s.Inventory.ListInventoryResources(ctx, scope, reader, search, inventoryPageSize+1)
	if err != nil {
		inventoryError(w, err)
		return
	}
	count := min(len(resources), inventoryPageSize)
	items := make([]map[string]any, 0, count)
	for _, resource := range resources[:count] {
		items = append(items, resource.view(scope))
	}
	response := map[string]any{"value": items}
	if len(resources) > count {
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(resources[count-1].Address.Key())))
		path := "/subscriptions/" + scope.SubscriptionID
		if group != "" {
			path += "/resourceGroups/" + url.PathEscape(group)
		}
		response["nextLink"] = s.Origin + path + "/providers/" + workload.ContainerGroupType + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s Server) containerLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, reader string, address ResourceAddress, name string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	query, ok := readQuery(w, r, workload.ContainerGroupAPIVersion, func(key, value string) bool { return key == "tail" && value != "" })
	if !ok {
		return
	}
	tail := 100
	if value := query.Get("tail"); value != "" {
		var err error
		if tail, err = strconv.Atoi(value); err != nil || tail < 1 || tail > 100 {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The log tail must be between 1 and 100 lines.")
			return
		}
	}
	resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
	if err != nil {
		inventoryError(w, err)
		return
	}
	if resource == nil || address.Path != workload.ContainerGroupType+"/"+name {
		containerError(w, ErrContainerMissing)
		return
	}
	content, err := s.Containers.ContainerLogs(ctx, scope, address, reader, tail)
	if err != nil {
		containerError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"content": content})
}

func containerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrStorageAccess), errors.Is(err, ErrStorageBusy), errors.Is(err, ErrStorageMissing):
		storageError(w, err)
	case errors.Is(err, workload.ErrInvalidContainer):
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", workload.ErrInvalidContainer.Error())
	case errors.Is(err, ErrContainerMissing):
		writeError(w, http.StatusNotFound, "ResourceNotFound", ErrContainerMissing.Error())
	case errors.Is(err, ErrContainerBusy):
		writeError(w, http.StatusConflict, "OperationInProgress", ErrContainerBusy.Error())
	case errors.Is(err, ErrContainerChanged):
		writeError(w, http.StatusConflict, "ContainerGroupConfigurationChanged", ErrContainerChanged.Error())
	case errors.Is(err, ErrContainerQuota):
		writeError(w, http.StatusConflict, "QuotaExceeded", ErrContainerQuota.Error())
	case errors.Is(err, ErrContainerDelegationRequired):
		writeError(w, http.StatusBadRequest, "SubnetDelegationRequired", ErrContainerDelegationRequired.Error())
	case errors.Is(err, ErrContainerNetworkConflict):
		writeError(w, http.StatusConflict, "OverlappingAddressSpace", ErrContainerNetworkConflict.Error())
	case errors.Is(err, ErrContainerCapacity):
		writeError(w, http.StatusServiceUnavailable, "InsufficientCapacity", ErrContainerCapacity.Error())
	default:
		inventoryError(w, err)
	}
}
