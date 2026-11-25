package arm

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/functions"
)

func functionPlanRoute(group string, path []string) (armRoute, bool) {
	if len(path) != 3 || !strings.EqualFold(strings.Join(path[:2], "/"), functions.PlanType) {
		return armRoute{}, false
	}
	return armRoute{collection: "functionPlan", group: group, name: path[2]}, true
}

var errFunctionPlanChanged = errors.New("changing the existing Functions plan profile is unsupported")

func (s Server) functionPlan(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, name string) {
	if !s.FunctionPlans {
		unavailable(w)
		return
	}
	if group == "" || !functions.ValidName(name) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The Functions plan identifier is invalid.")
		return
	}
	if _, ok := readQuery(w, r, functions.APIVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: functions.PlanType + "/" + name}
	switch r.Method {
	case http.MethodGet:
		plan, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if plan == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The Functions plan does not exist.")
		} else {
			writeJSON(w, http.StatusOK, functionPlanView(scope, *plan))
		}
	case http.MethodPut:
		var input functions.Plan
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 32<<10), &input); err != nil || !input.Valid(s.Location) || !validTags(input.Tags) {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", "Specify a one-worker Linux B1 Functions plan in the region.")
			return
		}
		plan, _, err := s.Networks.ChangeInventoryResource(ctx, scope, address, actor, functions.PlanType+"/write", "",
			func(current *InventoryResource, canonical ResourceAddress) (*InventoryResource, error) {
				if current != nil {
					if !maps.Equal(input.Tags, current.Tags) {
						return nil, errFunctionPlanChanged
					}
					return current, nil
				}
				data, _ := json.Marshal(map[string]any{"reserved": true, "provisioningState": OperationSucceeded, "status": "Ready",
					"numberOfWorkers": 1, "maximumNumberOfWorkers": 1})
				return &InventoryResource{Address: canonical, APIVersion: functions.APIVersion, Location: s.Location,
					Kind: "linux", SKU: ResourceSKU{Name: input.SKU.Name, Tier: input.SKU.Tier}, Tags: input.Tags,
					Properties: data, ProvisioningState: OperationSucceeded}, nil
			})
		if errors.Is(err, errFunctionPlanChanged) {
			writeError(w, http.StatusConflict, "ServicePlanConfigurationChanged", err.Error())
		} else if err != nil {
			inventoryError(w, err)
		} else {
			writeJSON(w, http.StatusOK, functionPlanView(scope, *plan))
		}
	case http.MethodDelete:
		_, _, err := s.Networks.ChangeInventoryResource(ctx, scope, address, actor, functions.PlanType+"/delete", "",
			func(*InventoryResource, ResourceAddress) (*InventoryResource, error) { return nil, nil })
		if errors.Is(err, ErrLinkedResourceInUse) {
			writeError(w, http.StatusConflict, "ServicePlanInUse", "The Functions plan still has an app.")
		} else if err != nil && !errors.Is(err, ErrGroupMissing) {
			inventoryError(w, err)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

func functionPlanView(scope SubscriptionScope, plan InventoryResource) map[string]any {
	view := plan.view(scope)
	view["sku"] = functions.SKU{Name: plan.SKU.Name, Tier: plan.SKU.Tier, Capacity: 1}
	return view
}
