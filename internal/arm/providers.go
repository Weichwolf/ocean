package arm

import (
	"net/http"
	"strings"
)

type providerResourceType struct {
	ResourceType string   `json:"resourceType"`
	Locations    []string `json:"locations"`
	APIVersions  []string `json:"apiVersions"`
}

type providerView struct {
	ID                 string                 `json:"id"`
	Namespace          string                 `json:"namespace"`
	RegistrationState  string                 `json:"registrationState"`
	RegistrationPolicy string                 `json:"registrationPolicy"`
	ResourceTypes      []providerResourceType `json:"resourceTypes"`
}

func (s Server) provider(w http.ResponseWriter, r *http.Request, scope SubscriptionScope, namespace string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if _, ok := readQuery(w, r, resourceAPIVersion, nil); !ok {
		return
	}
	if !strings.EqualFold(namespace, "Microsoft.Resources") {
		writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
		return
	}
	writeJSON(w, http.StatusOK, providerView{
		ID:                 "/subscriptions/" + scope.SubscriptionID + "/providers/Microsoft.Resources",
		Namespace:          "Microsoft.Resources",
		RegistrationState:  "Registered",
		RegistrationPolicy: "RegistrationFree",
		ResourceTypes:      []providerResourceType{{ResourceType: "resourceGroups", Locations: []string{s.Location}, APIVersions: []string{resourceAPIVersion}}},
	})
}
