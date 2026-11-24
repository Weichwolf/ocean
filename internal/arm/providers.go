package arm

import (
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
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
	var types []providerResourceType
	switch strings.ToLower(namespace) {
	case "microsoft.resources":
		namespace = "Microsoft.Resources"
		types = []providerResourceType{{ResourceType: "resourceGroups", Locations: []string{s.Location}, APIVersions: []string{resourceAPIVersion}}}
	case "microsoft.network":
		namespace = "Microsoft.Network"
		types = []providerResourceType{
			{ResourceType: "virtualNetworks", Locations: []string{s.Location}, APIVersions: []string{network.VNetAPIVersion}},
			{ResourceType: "virtualNetworks/subnets", Locations: []string{s.Location}, APIVersions: []string{network.SubnetAPIVersion}},
			{ResourceType: "networkSecurityGroups", Locations: []string{s.Location}, APIVersions: []string{network.SecurityGroupAPIVersion}},
			{ResourceType: "networkSecurityGroups/securityRules", Locations: []string{s.Location}, APIVersions: []string{network.SecurityGroupAPIVersion}},
			{ResourceType: "publicIPAddresses", Locations: []string{s.Location}, APIVersions: []string{network.PublicIPAPIVersion}},
			{ResourceType: "natGateways", Locations: []string{s.Location}, APIVersions: []string{network.NATAPIVersion}},
		}
	case "microsoft.authorization":
		namespace = "Microsoft.Authorization"
		types = []providerResourceType{
			{ResourceType: "roleAssignments", Locations: []string{}, APIVersions: []string{assignmentAPIVersion}},
			{ResourceType: "roleDefinitions", Locations: []string{}, APIVersions: []string{definitionAPIVersion}},
		}
	default:
		writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
		return
	}
	writeJSON(w, http.StatusOK, providerView{
		ID:                 "/subscriptions/" + scope.SubscriptionID + "/providers/" + namespace,
		Namespace:          namespace,
		RegistrationState:  "Registered",
		RegistrationPolicy: "RegistrationFree",
		ResourceTypes:      types,
	})
}
