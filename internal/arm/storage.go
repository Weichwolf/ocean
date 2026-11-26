package arm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/storage"
)

var (
	ErrStorageMissing   = errors.New("the storage account or file share does not exist")
	ErrStorageNameInUse = errors.New("the storage account name is already registered")
	ErrStorageBusy      = errors.New("the file share has a pending operation or authorized writer")
	ErrStorageChanged   = errors.New("the existing storage resource has different settings")
	ErrStorageAccess    = errors.New("the storage account key does not authorize this mount")
)

type StorageStore interface {
	ApplyStorageFence(context.Context, storage.SignedFence) error
	StorageNameAvailable(context.Context, string) (bool, error)
	PutStorageAccount(context.Context, SubscriptionScope, string, ResourceAddress, storage.AccountRequest) (InventoryResource, bool, error)
	GetStorageAccountKeys(context.Context, SubscriptionScope, string, ResourceAddress) ([2]string, error)
	DeleteStorageAccount(context.Context, SubscriptionScope, string, ResourceAddress) error
	PutFileShare(context.Context, SubscriptionScope, string, ResourceAddress, ResourceAddress, storage.ShareProperties) (InventoryResource, *Operation, bool, error)
	DeleteFileShare(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func storageRoute(group string, path []string) (armRoute, bool) {
	if len(path) < 2 || !strings.EqualFold(path[0], "Microsoft.Storage") {
		return armRoute{}, false
	}
	if group == "" && len(path) == 2 && strings.EqualFold(path[1], "checkNameAvailability") {
		return armRoute{collection: "storageNameAvailability"}, true
	}
	if strings.EqualFold(path[1], "storageAccounts") {
		return armRoute{collection: "storageAccount", group: group, name: strings.Join(path[2:], "/")}, true
	}
	return armRoute{}, false
}

func (s Server) storageNameAvailability(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if s.Storage == nil {
		unavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if _, ok := readQuery(w, r, storage.AccountAPIVersion, nil); !ok {
		return
	}
	var input struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err != nil || input.Type != storage.AccountType {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "Specify a valid storage account name and resource type.")
		return
	}
	if !storage.ValidAccount(input.Name) {
		writeJSON(w, http.StatusOK, map[string]any{"nameAvailable": false, "reason": "AccountNameInvalid"})
		return
	}
	available, err := s.Storage.StorageNameAvailable(ctx, input.Name)
	if err != nil {
		unavailable(w)
		return
	}
	result := map[string]any{"nameAvailable": available}
	if !available {
		result["reason"] = "AlreadyExists"
	}
	writeJSON(w, http.StatusOK, result)
}

func (s Server) storageAccount(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, path string) {
	if s.Storage == nil {
		unavailable(w)
		return
	}
	parts := strings.Split(path, "/")
	if group == "" || !storage.ValidAccount(parts[0]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The storage account identifier is invalid.")
		return
	}
	account := ResourceAddress{Group: group, Path: storage.AccountType + "/" + parts[0]}
	if len(parts) == 5 && strings.EqualFold(parts[1], "fileServices") && strings.EqualFold(parts[2], "default") &&
		strings.EqualFold(parts[3], "shares") && storage.ValidShare(parts[4]) {
		share := ResourceAddress{Group: group, Path: account.Path + "/fileServices/default/shares/" + parts[4]}
		s.fileShare(ctx, w, r, scope, actor, reader, account, share)
		return
	}
	listKeys := len(parts) == 2 && strings.EqualFold(parts[1], "listKeys") && r.Method == http.MethodPost
	if _, ok := readQuery(w, r, storage.AccountAPIVersion, func(key, value string) bool {
		// The generated client asks for the optional Kerberos key set on
		// every listKeys call. This account supports standard shared keys.
		return listKeys && key == "$expand" && value == "kerb"
	}); !ok {
		return
	}
	if listKeys {
		keys, err := s.Storage.GetStorageAccountKeys(ctx, scope, actor, account)
		if err != nil {
			storageError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{
			{"keyName": "key1", "permissions": "Full", "value": keys[0]},
			{"keyName": "key2", "permissions": "Full", "value": keys[1]},
		}})
		return
	}
	if len(parts) != 1 {
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The storage account operation is unsupported.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.showStorageResource(ctx, w, scope, reader, account)
	case http.MethodPut:
		var input storage.AccountRequest
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 32<<10), &input); err != nil || !input.Valid(s.Location) || !validTags(input.Tags) {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The requested storage account configuration is unsupported.")
			return
		}
		resource, _, err := s.Storage.PutStorageAccount(ctx, scope, actor, account, input)
		if err != nil {
			storageError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, s.storageView(scope, resource))
	case http.MethodDelete:
		if err := s.Storage.DeleteStorageAccount(ctx, scope, actor, account); err != nil {
			storageError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) fileShare(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader string,
	account, share ResourceAddress) {
	if _, ok := readQuery(w, r, storage.ShareAPIVersion, func(key, value string) bool {
		return r.Method == http.MethodDelete && key == "$include" && value == "none"
	}); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.showStorageResource(ctx, w, scope, reader, share)
	case http.MethodPut:
		var input storage.ShareRequest
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 8192), &input); err != nil || !input.Properties.Valid() {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "The requested file share configuration is unsupported.")
			return
		}
		resource, operation, created, err := s.Storage.PutFileShare(ctx, scope, actor, account, share, input.Properties)
		if err != nil {
			storageError(w, err)
			return
		}
		// The pinned share CLI expects an ordinary 200 or 201 response and
		// does not poll. Wait for the filesystem acknowledgement first.
		if operation != nil && operation.Status != OperationSucceeded {
			if err := s.awaitShare(ctx, scope, operation); err != nil {
				storageError(w, err)
				return
			}
			s.showStorageResource(ctx, w, scope, reader, share)
			return
		}
		writeJSON(w, createdStatus(created), resource.view(scope))
	case http.MethodDelete:
		operation, err := s.Storage.DeleteFileShare(ctx, scope, actor, share)
		if err == nil && operation != nil {
			err = s.awaitShare(ctx, scope, operation)
		}
		if err != nil {
			storageError(w, err)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) awaitShare(ctx context.Context, scope SubscriptionScope, op *Operation) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for op.Status == OperationInProgress {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := s.Operations.GetOperation(ctx, scope, op.ID)
			if err != nil {
				return err
			}
			if current == nil {
				return ErrStorageMissing
			}
			op = current
		}
	}
	if op.Status != OperationSucceeded {
		return ErrStorageBusy
	}
	return nil
}

func (s Server) showStorageResource(ctx context.Context, w http.ResponseWriter, scope SubscriptionScope, reader string, address ResourceAddress) {
	resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
	if err != nil {
		storageError(w, err)
	} else if resource == nil {
		storageError(w, ErrStorageMissing)
	} else {
		writeJSON(w, http.StatusOK, s.storageView(scope, *resource))
	}
}

func (s Server) storageView(scope SubscriptionScope, resource InventoryResource) map[string]any {
	view := resource.view(scope)
	name, kind, _ := resource.Address.parts()
	if kind != storage.AccountType || s.StorageSuffix == "" {
		return view
	}
	var properties map[string]any
	if json.Unmarshal(resource.Properties, &properties) != nil {
		return view
	}
	endpoints := make(map[string]string, 3)
	for _, service := range []string{"blob", "queue", "table"} {
		endpoints[service] = "https://" + name + "." + service + "." + s.StorageSuffix + "/"
	}
	properties["primaryEndpoints"] = endpoints
	view["properties"] = properties
	return view
}

func storageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrStorageMissing):
		writeError(w, http.StatusNotFound, "ResourceNotFound", ErrStorageMissing.Error())
	case errors.Is(err, ErrStorageNameInUse):
		writeError(w, http.StatusConflict, "StorageAccountAlreadyTaken", ErrStorageNameInUse.Error())
	case errors.Is(err, ErrStorageBusy):
		writeError(w, http.StatusConflict, "StorageResourceInUse", ErrStorageBusy.Error())
	case errors.Is(err, ErrStorageChanged):
		writeError(w, http.StatusConflict, "StorageResourceConfigurationChanged", ErrStorageChanged.Error())
	case errors.Is(err, ErrStorageAccess):
		writeError(w, http.StatusForbidden, "StorageAuthorizationFailed", ErrStorageAccess.Error())
	case errors.Is(err, ErrContainerCapacity):
		writeError(w, http.StatusServiceUnavailable, "InsufficientCapacity", "No eligible storage worker is available.")
	default:
		inventoryError(w, err)
	}
}

func (s Server) storageFence(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if s.Storage == nil || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	var request storage.SignedFence
	if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &request); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestContent", "A signed writer fence attestation is required.")
		return
	}
	if err := s.Storage.ApplyStorageFence(ctx, request); err != nil {
		storageError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
