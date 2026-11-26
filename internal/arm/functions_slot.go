package arm

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/Weichwolf/ocean/internal/functions"
)

type FunctionSlotStore interface {
	CreateFunctionSlot(context.Context, SubscriptionScope, string, ResourceAddress, string, string) (InventoryResource, *Operation, error)
	ListFunctionSlots(context.Context, SubscriptionScope, string, ResourceAddress, string, int) ([]InventoryResource, error)
	FunctionSlotSettings(context.Context, SubscriptionScope, string, ResourceAddress) ([]string, error)
	SetFunctionSlotSettings(context.Context, SubscriptionScope, string, ResourceAddress, []string) error
	SwapFunctionSlot(context.Context, SubscriptionScope, string, ResourceAddress, string) (*Operation, error)
}

func (s Server) functionSlot(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, parent ResourceAddress, path string, query url.Values) {
	if s.FunctionSlots == nil {
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "Functions slots are disabled.")
		return
	}
	if strings.EqualFold(path, "slots") {
		s.listFunctionSlots(ctx, w, r, scope, reader, parent, query)
		return
	}
	_, rest, _ := strings.Cut(path, "/")
	name, child, nested := strings.Cut(rest, "/")
	address := ResourceAddress{Group: parent.Group, Path: parent.Path + "/slots/" + name}
	app, _, valid := functions.SlotNames(address.Path)
	host := app + "-" + name
	if !valid || !functions.ValidName(host) || nested && child == "" {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	switch strings.ToLower(child) {
	case "":
		s.functionSlotResource(ctx, w, r, scope, actor, reader, address, host)
	case "slotsswap":
		s.swapFunctionSlot(ctx, w, r, scope, actor, address)
	case "config/appsettings", "config/appsettings/list":
		s.functionConfiguration(ctx, w, r, scope, actor, reader, address, strings.ToLower(child))
	case "basicpublishingcredentialspolicies/scm":
		s.functionSCMPolicy(ctx, w, r, scope, reader, address)
	default:
		if lower := strings.ToLower(child); lower == "functions" || strings.HasPrefix(lower, "functions/") {
			s.functionKeysAndDiscovery(ctx, w, r, scope, actor, reader, address, child)
			return
		}
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The Functions slot operation is unsupported.")
	}
}

func (s Server) functionSlotResource(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, address ResourceAddress, label string) {
	switch r.Method {
	case http.MethodGet:
		if resource := s.getFunctionSite(ctx, w, scope, reader, address); resource != nil {
			writeJSON(w, http.StatusOK, s.functionSiteView(scope, *resource))
		}
	case http.MethodPut:
		var input struct {
			Location   string `json:"location"`
			Properties struct {
				HTTPSOnly    bool   `json:"httpsOnly"`
				ServerFarmID string `json:"serverFarmId"`
			} `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 16<<10), &input); err != nil ||
			input.Location != s.Location || !input.Properties.HTTPSOnly || input.Properties.ServerFarmID == "" {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		resource, op, err := s.FunctionSlots.CreateFunctionSlot(ctx, scope, actor, address, input.Properties.ServerFarmID, label+"."+s.FunctionDomain)
		if err != nil {
			containerError(w, err)
			return
		}
		s.writeFunctionCreate(w, scope, resource, op)
	case http.MethodDelete:
		s.functionLifecycle(ctx, w, scope, actor, address, "delete")
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func (s Server) listFunctionSlots(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, parent ResourceAddress, query url.Values) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	after := ""
	if token := query.Get("$skiptoken"); token != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		after = string(decoded)
		if err != nil || !functions.ValidName(after) || after == "production" {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The Functions slot continuation is invalid.")
			return
		}
	}
	resources, err := s.FunctionSlots.ListFunctionSlots(ctx, scope, reader, parent, after, inventoryPageSize+1)
	if err != nil {
		containerError(w, err)
		return
	}
	count := min(len(resources), inventoryPageSize)
	items := make([]map[string]any, 0, count)
	for _, item := range resources[:count] {
		items = append(items, s.functionSiteView(scope, item))
	}
	reply := map[string]any{"value": items}
	if len(resources) > count {
		_, slot, _ := functions.SlotNames(resources[count-1].Address.Path)
		query.Set("$skiptoken", base64.RawURLEncoding.EncodeToString([]byte(slot)))
		reply["nextLink"] = s.Origin + r.URL.EscapedPath() + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, reply)
}

func (s Server) swapFunctionSlot(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor string, address ResourceAddress) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var input struct {
		TargetSlot   string `json:"targetSlot"`
		PreserveVNet bool   `json:"preserveVnet"`
	}
	requestID := strings.ToLower(r.Header.Get("x-ms-client-request-id"))
	if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err != nil || input.TargetSlot != "production" ||
		!input.PreserveVNet || requestID != "" && !validUUID.MatchString(requestID) {
		containerError(w, functions.ErrInvalidSite)
		return
	}
	op, err := s.FunctionSlots.SwapFunctionSlot(ctx, scope, actor, address, requestID)
	if err != nil {
		containerError(w, err)
		return
	}
	s.acceptOperation(w, scope, *op)
}

type functionSlotSettings struct {
	AppSettingNames         []string `json:"appSettingNames"`
	ConnectionStringNames   []string `json:"connectionStringNames,omitempty"`
	AzureStorageConfigNames []string `json:"azureStorageConfigNames,omitempty"`
}

func (s Server) functionSlotSettings(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, address ResourceAddress) {
	if s.getFunctionSite(ctx, w, scope, reader, address) == nil {
		return
	}
	reply := struct {
		Properties functionSlotSettings `json:"properties"`
	}{Properties: functionSlotSettings{AppSettingNames: []string{}}}
	switch {
	case r.Method == http.MethodGet && s.FunctionSlots == nil:
	case r.Method == http.MethodGet:
		names, err := s.FunctionSlots.FunctionSlotSettings(ctx, scope, reader, address)
		if err != nil {
			containerError(w, err)
			return
		}
		reply.Properties.AppSettingNames = names
	case r.Method == http.MethodPut && s.FunctionSlots != nil:
		reply.Properties = functionSlotSettings{}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 16<<10), &reply); err != nil || reply.Properties.AppSettingNames == nil ||
			len(reply.Properties.ConnectionStringNames) != 0 || len(reply.Properties.AzureStorageConfigNames) != 0 ||
			!functions.ValidStickySettings(reply.Properties.AppSettingNames) {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		if err := s.FunctionSlots.SetFunctionSlotSettings(ctx, scope, actor, address, reply.Properties.AppSettingNames); err != nil {
			containerError(w, err)
			return
		}
	default:
		if s.FunctionSlots == nil {
			methodNotAllowed(w, "GET")
		} else {
			methodNotAllowed(w, "GET, PUT")
		}
		return
	}
	writeJSON(w, http.StatusOK, reply)
}
