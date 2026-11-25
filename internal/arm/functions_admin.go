package arm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/functions"
)

func (s Server) functionKeysAndDiscovery(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader string, address ResourceAddress, child string) {
	resource := s.getFunctionSite(ctx, w, scope, reader, address)
	if resource == nil {
		return
	}
	path := strings.Split(child, "/")
	var request functions.AdminRequest
	switch {
	case len(path) == 1 && r.Method == http.MethodGet:
	case len(path) == 3 && strings.EqualFold(path[2], "listkeys") && r.Method == http.MethodPost:
		request.Function = path[1]
	case len(path) == 4 && strings.EqualFold(path[2], "keys") && r.Method == http.MethodPut:
		var input struct {
			Properties functions.Setting `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err != nil ||
			input.Properties.Name != path[3] || !functions.ValidFunctionName(path[3]) || !functions.ValidKey(input.Properties.Value) {
			containerError(w, functions.ErrInvalidSite)
			return
		}
		request.Function, request.Name, request.Value = path[1], path[3], input.Properties.Value
	default:
		writeError(w, http.StatusBadRequest, "UnsupportedOperation", "The Functions discovery or key operation is unsupported.")
		return
	}
	if len(path) > 1 && (!functions.ValidFunctionName(request.Function) || reader != "") {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal cannot manage Function keys.")
		return
	}
	result, err := s.Functions.RunFunctionAdmin(ctx, scope, actor, address, request)
	if err != nil {
		containerError(w, err)
		return
	}
	if result.Status < 200 || result.Status >= 300 {
		functionNativeError(w, result.Status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if len(path) == 1 {
		s.functionDiscovery(w, scope, *resource, result.Body)
		return
	}
	if request.Name == "" {
		var state struct {
			Keys []functions.Setting `json:"keys"`
		}
		if json.Unmarshal(result.Body, &state) != nil {
			unavailable(w)
			return
		}
		keys := make(map[string]string, len(state.Keys))
		for _, key := range state.Keys {
			keys[key.Name] = key.Value
		}
		writeJSON(w, http.StatusOK, map[string]any{"properties": keys})
		return
	}
	var key functions.Setting
	if json.Unmarshal(result.Body, &key) != nil || key != (functions.Setting{Name: request.Name, Value: request.Value}) {
		unavailable(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"properties": key})
}

func (s Server) functionDiscovery(w http.ResponseWriter, scope SubscriptionScope, resource InventoryResource, data []byte) {
	var discovered []struct {
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
		Route  string          `json:"invoke_url_template"`
	}
	if json.Unmarshal(data, &discovered) != nil {
		unavailable(w)
		return
	}
	site, _, _ := resource.Address.parts()
	items := make([]map[string]any, 0, len(discovered))
	for _, function := range discovered {
		if !functions.ValidFunctionName(function.Name) {
			continue
		}
		route := "/api/" + function.Name
		if _, suffix, ok := strings.Cut(function.Route, "/api/"); ok && suffix != "" && !strings.ContainsAny(suffix, "\r\n?#") {
			route = "/api/" + suffix
		}
		properties := map[string]any{"name": function.Name, "config": function.Config,
			"invokeUrlTemplate": "https://" + site + "." + s.FunctionDomain + route}
		items = append(items, map[string]any{"name": site + "/" + function.Name,
			"id": resource.Address.ID(scope) + "/functions/" + function.Name, "type": functions.SiteType + "/functions", "properties": properties})
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": items})
}
