package arm

import (
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/functions"
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
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
		types = []providerResourceType{
			{ResourceType: "resourceGroups", Locations: []string{s.Location}, APIVersions: []string{resourceAPIVersion}},
			{ResourceType: "deployments", Locations: []string{s.Location}, APIVersions: []string{deploymentAPIVersion}},
		}
	case "microsoft.network":
		namespace = "Microsoft.Network"
		types = []providerResourceType{
			{ResourceType: "virtualNetworks", Locations: []string{s.Location}, APIVersions: []string{network.VNetAPIVersion}},
			{ResourceType: "virtualNetworks/subnets", Locations: []string{s.Location}, APIVersions: []string{network.SubnetAPIVersion, network.ContainerSubnetAPIVersion}},
			{ResourceType: "networkSecurityGroups", Locations: []string{s.Location}, APIVersions: []string{network.SecurityGroupAPIVersion}},
			{ResourceType: "networkSecurityGroups/securityRules", Locations: []string{s.Location}, APIVersions: []string{network.SecurityGroupAPIVersion}},
			{ResourceType: "publicIPAddresses", Locations: []string{s.Location}, APIVersions: []string{network.PublicIPAPIVersion}},
			{ResourceType: "natGateways", Locations: []string{s.Location}, APIVersions: []string{network.NATAPIVersion}},
		}
		if s.Functions != nil {
			types[0].APIVersions = append(types[0].APIVersions, network.ContainerSubnetAPIVersion)
		}
	case "microsoft.web":
		if !s.FunctionPlans {
			writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
			return
		}
		namespace = "Microsoft.Web"
		types = []providerResourceType{{ResourceType: "serverfarms", Locations: []string{s.Location}, APIVersions: []string{functions.APIVersion}}}
		if s.Functions != nil {
			types = append(types, providerResourceType{ResourceType: "sites", Locations: []string{s.Location}, APIVersions: []string{functions.APIVersion, functions.SiteReadAPIVersion}})
		}
	case "microsoft.storage":
		if s.Storage == nil {
			writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
			return
		}
		namespace = "Microsoft.Storage"
		types = []providerResourceType{
			{ResourceType: "storageAccounts", Locations: []string{s.Location}, APIVersions: []string{storage.AccountAPIVersion}},
			{ResourceType: "storageAccounts/fileServices/shares", Locations: []string{s.Location}, APIVersions: []string{storage.ShareAPIVersion}},
		}
	case "microsoft.containerinstance":
		if s.Containers == nil {
			writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
			return
		}
		namespace = "Microsoft.ContainerInstance"
		types = []providerResourceType{{ResourceType: "containerGroups", Locations: []string{s.Location}, APIVersions: []string{workload.ContainerGroupAPIVersion}}}
	case "ocean.compute":
		if s.ReplicaSets == nil {
			writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
			return
		}
		namespace = "Ocean.Compute"
		types = []providerResourceType{{ResourceType: "replicaSets", Locations: []string{s.Location}, APIVersions: []string{workload.ReplicaSetAPIVersion}}}
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
