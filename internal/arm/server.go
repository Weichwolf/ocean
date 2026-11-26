// Package arm implements the supported Azure Resource Manager contract.
package arm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
	"github.com/Weichwolf/ocean/internal/identity"
	"github.com/Weichwolf/ocean/internal/smb"
	"github.com/Weichwolf/ocean/internal/workload"
)

const resourceAPIVersion = "2024-11-01"

type Server struct {
	Origin              string
	Location            string
	Authenticate        func(context.Context, *http.Request) (identity.ARMPrincipal, error)
	AuthenticateDesktop func(context.Context, *http.Request) (identity.DesktopPrincipal, error)
	Groups              GroupStore
	Roles               RoleStore
	Operations          OperationStore
	Monitor             MonitorStore
	Inventory           InventoryStore
	Networks            NetworkStore
	Deployments         NetworkDeploymentStore
	GatewayDeployments  ApplicationGatewayDeploymentStore
	VPN                 VPNStore
	SiteConnections     SiteConnectionStore
	Containers          ContainerGroupStore
	VirtualMachines     VirtualMachineStore
	ReplicaSets         ReplicaSetStore
	Storage             StorageStore
	SMBShares           SMBStore
	Desktops            DesktopStore
	DesktopLaunch       DesktopLaunchStore
	DesktopCIFS         DesktopCIFSStore
	DesktopNative       DesktopNativeStore
	FunctionPlans       bool
	Functions           FunctionStore
	FunctionPackages    FunctionPackageDeployments
	FunctionSlots       FunctionSlotStore
	FunctionDomain      string
	FunctionSCMDomain   string
	FunctionRegistry    string
	StorageSuffix       string
	PrincipalExists     func(context.Context, string, string, string) (bool, error)
}

type armRoute struct {
	collection string
	group      string
	name       string
}

func parseRoute(segments []string) armRoute {
	if len(segments) < 3 || !strings.EqualFold(segments[0], "subscriptions") {
		return armRoute{}
	}
	if route, ok := monitorRoute(segments); ok {
		return route
	}
	if len(segments) == 4 && strings.EqualFold(segments[2], "providers") {
		return armRoute{collection: "providers", name: segments[3]}
	}
	if len(segments) == 3 && strings.EqualFold(segments[2], "resources") {
		return armRoute{collection: "inventory"}
	}
	if len(segments) == 5 && strings.EqualFold(segments[2], "providers") {
		if route, ok := storageRoute("", segments[3:]); ok {
			return route
		}
		if route, ok := functionSiteRoute("", segments[3:]); ok {
			return route
		}
		if route, ok := containerRoute("", segments[3:]); ok {
			return route
		}
		if route, ok := networkRoute("", segments[3:]); ok {
			return route
		}
	}
	if len(segments) == 6 && strings.EqualFold(segments[2], "providers") && strings.EqualFold(segments[3], "Microsoft.Resources") {
		collection := strings.ToLower(segments[4])
		if collection == "operationstatuses" || collection == "operationresults" {
			return armRoute{collection: collection, name: segments[5]}
		}
	}
	var group string
	start := 2
	if strings.EqualFold(segments[2], "resourcegroups") {
		if len(segments) == 3 {
			return armRoute{collection: "groups"}
		}
		group = segments[3]
		if !validGroupName(group) {
			return armRoute{collection: "invalidGroup"}
		}
		if len(segments) == 4 {
			return armRoute{collection: "groups", group: group}
		}
		if len(segments) == 5 && strings.EqualFold(segments[4], "resources") {
			return armRoute{collection: "inventory", group: group}
		}
		if len(segments) >= 7 && strings.EqualFold(segments[4], "providers") {
			if len(segments) == 9 && strings.EqualFold(segments[5]+"/"+segments[6], DesktopType) {
				switch strings.ToLower(segments[8]) {
				case "authorize":
					return armRoute{collection: "desktopAuthorization", group: group, name: segments[7]}
				case "launch":
					return armRoute{collection: "desktopLaunch", group: group, name: segments[7]}
				case "renew":
					return armRoute{collection: "desktopRenew", group: group, name: segments[7]}
				}
			}
			if len(segments) == 8 && strings.EqualFold(segments[5]+"/"+segments[6], DesktopType) {
				return armRoute{collection: "personalDesktop", group: group, name: segments[7]}
			}
			if len(segments) == 8 && strings.EqualFold(segments[5]+"/"+segments[6], smb.ResourceType) {
				return armRoute{collection: "smbShare", group: group, name: segments[7]}
			}
			if route, ok := virtualMachineRoute(group, segments[5:]); ok {
				return route
			}
			if len(segments) == 8 && strings.EqualFold(strings.Join(segments[5:7], "/"), workload.ReplicaSetType) {
				return armRoute{collection: "replicaSet", group: group, name: segments[7]}
			}
			if route, ok := functionSiteRoute(group, segments[5:]); ok {
				return route
			}
			if route, ok := functionPlanRoute(group, segments[5:]); ok {
				return route
			}
			if route, ok := storageRoute(group, segments[5:]); ok {
				return route
			}
			if route, ok := containerRoute(group, segments[5:]); ok {
				return route
			}
			if route, ok := networkRoute(group, segments[5:]); ok {
				return route
			}
			if (len(segments) == 8 || len(segments) == 9) &&
				strings.EqualFold(segments[5]+"/"+segments[6], deploymentType) {
				name := segments[7]
				if len(segments) == 9 {
					name += "/" + strings.ToLower(segments[8])
				}
				return armRoute{collection: "deployment", group: group, name: name}
			}
		}
		start = 4
	}
	if (len(segments) != start+3 && len(segments) != start+4) || !strings.EqualFold(segments[start], "providers") ||
		!strings.EqualFold(segments[start+1], "Microsoft.Authorization") {
		if group != "" && len(segments) >= 8 && strings.EqualFold(segments[4], "providers") {
			return armRoute{collection: "resource", group: group, name: strings.Join(segments[5:], "/")}
		}
		return armRoute{}
	}
	collection := strings.ToLower(segments[start+2])
	if collection != "roleassignments" && collection != "roledefinitions" {
		return armRoute{}
	}
	route := armRoute{collection: collection, group: group}
	if len(segments) == start+4 {
		route.name = segments[start+3]
		if !validUUID.MatchString(route.name) {
			route.collection = "invalidRoleID"
		}
	}
	return route
}

func networkRoute(group string, path []string) (armRoute, bool) {
	route := armRoute{group: group}
	if group != "" && strings.EqualFold(path[0], "Ocean.Network") && strings.EqualFold(path[1], "siteConnections") {
		route.collection = "siteConnection"
		route.name = strings.Join(path, "/")
		return route, true
	}
	if !strings.EqualFold(path[0], "Microsoft.Network") {
		return route, false
	}
	switch strings.ToLower(path[1]) {
	case "virtualnetworks":
		route.collection = "network"
	case "networksecuritygroups":
		route.collection = "securityGroup"
	case "publicipaddresses", "natgateways":
		route.collection = "egress"
	case "applicationgateways":
		if group == "" {
			return route, false
		}
		route.collection = "applicationGateway"
	case "virtualnetworkgateways", "localnetworkgateways", "connections":
		if group == "" {
			return route, false
		}
		route.collection = "vpn"
	default:
		return route, false
	}
	route.name = strings.Join(path, "/")
	return route, true
}

// Handler serves ARM routes over the same ingress as identity and discovery.
func (s Server) Handler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app, ok := s.functionSCMHost(r.Host); ok {
			s.functionSCM(w, r, app)
			return
		}
		if r.URL.Path == desktop.NativeAdmissionPath && strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			s.desktopNativeAdmission(w, r)
			return
		}
		if r.URL.Path == desktop.KerberosPath && strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			s.desktopKerberos(w, r)
			return
		}
		if r.URL.Path == "/ocean/storage/smb-fences" && strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			s.smbFence(ctx, w, r)
			return
		}
		if r.URL.Path == "/ocean/storage/fences" && strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			s.storageFence(ctx, w, r)
			return
		}
		if strings.EqualFold(r.URL.Path, functionStacksPath) && strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			s.functionStacks(w, r.WithContext(ctx))
			return
		}
		segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		route := parseRoute(segments)
		if len(segments) == 10 && segments[0] == "v1" {
			segments = segments[1:]
			route = resourceLogsRoute(segments)
		}
		if route.collection == "" || !strings.EqualFold(r.Host, strings.TrimPrefix(s.Origin, "https://")) {
			fallback.ServeHTTP(w, r)
			return
		}
		if route.collection == "desktopAuthorization" || route.collection == "desktopLaunch" || route.collection == "desktopRenew" {
			s.authorizePersonalDesktop(w, r, segments[1], route.group, route.name, route.collection)
			return
		}
		timeout := 5 * time.Second
		if route.collection == "functionSite" || route.collection == "personalDesktop" && r.Method == http.MethodPut {
			timeout = 27 * time.Second
		}
		if route.collection == "storageAccount" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.Contains(strings.ToLower(route.name), "/fileservices/default/shares/") {
			timeout = 25 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		principal, ok := s.subscriptionPrincipal(ctx, w, r, segments[1])
		if !ok {
			return
		}
		entry := principal.Subscription
		scope := SubscriptionScope{TenantID: entry.TenantID, SubscriptionID: entry.SubscriptionID}
		reader := ""
		if !slices.Contains(entry.Members, principal.Subject) {
			if !s.authorizeReader(ctx, w, r, scope, route, principal.Subject) {
				return
			}
			reader = principal.Subject
		}
		switch route.collection {
		case "groups":
			s.group(ctx, w, r, scope, route.group, principal.Subject, reader)
		case "providers":
			s.provider(w, r, scope, route.name)
		case "roledefinitions":
			s.roleDefinitions(w, r, scope, route.name)
		case "roleassignments":
			s.roleAssignments(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "operationstatuses", "operationresults":
			s.operation(ctx, w, r, scope, route.collection, route.name)
		case "inventory":
			s.listResources(ctx, w, r, scope, reader, route.group)
		case "network":
			s.network(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "applicationGateway":
			s.applicationGatewayResource(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "vpn":
			s.vpnResource(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "resourceLogs":
			s.resourceLogs(ctx, w, r, scope, reader, ResourceAddress{Group: route.group, Path: route.name})
		case "activityLog", "regionUsage", "resourceHealth", "workloadMetrics":
			s.monitor(ctx, w, r, scope, reader, route)
		case "functionSite":
			s.functionSite(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "functionPlan":
			s.functionPlan(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "storageNameAvailability":
			s.storageNameAvailability(ctx, w, r)
		case "storageAccount":
			s.storageAccount(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "smbShare":
			s.smbShare(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "personalDesktop":
			s.personalDesktop(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "replicaSet":
			s.replicaSet(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "containerGroup":
			s.containerGroup(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "virtualMachine":
			s.virtualMachineResource(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "siteConnection":
			s.siteConnection(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "securityGroup":
			s.securityGroup(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "egress":
			s.egressResource(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "deployment":
			s.deployment(ctx, w, r, scope, principal.Subject, reader, route.group, route.name)
		case "resource":
			s.showResource(ctx, w, r, scope, reader, ResourceAddress{Group: route.group, Path: route.name})
		case "invalidGroup":
			writeError(w, http.StatusBadRequest, "InvalidResourceGroup", "The resource group name is invalid.")
		case "invalidRoleID":
			writeError(w, http.StatusBadRequest, "InvalidRoleAssignmentId", "The resource identifier must be a UUID.")
		}
	})
}

func (s Server) authorizeReader(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, route armRoute, subject string) bool {
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	networkResource := route.collection == "network" || route.collection == "securityGroup" || route.collection == "egress" || route.collection == "vpn"
	functionRead := route.collection == "functionSite" && !strings.Contains(strings.ToLower(route.name), "/keys")
	if functionRead && r.Method == http.MethodPost && strings.HasSuffix(strings.ToLower(route.name), "/publishxml") {
		return true // The handler applies group scope and returns only the OCI deployment method.
	}
	if route.collection == "resourceLogs" && r.Method == http.MethodPost {
		return true // Log queries apply the group grant in the same store read.
	}
	if read && (route.collection == "replicaSet" || route.collection == "workloadMetrics" || route.collection == "resourceHealth" || route.collection == "activityLog" ||
		route.collection == "groups" || route.collection == "inventory" || route.collection == "resource" || route.collection == "deployment" || networkResource || route.collection == "containerGroup" || route.collection == "virtualMachine" || route.collection == "storageAccount" || route.collection == "functionPlan" || functionRead ||
		route.collection == "smbShare" || route.collection == "personalDesktop" || route.collection == "roleassignments" && route.group != "") {
		return true // Scoped reads apply the grant in the same store operation as the resource read.
	}
	if read && route.collection != "operationstatuses" && route.collection != "operationresults" {
		var granted bool
		var err error
		if route.group != "" {
			granted, err = s.Roles.GroupGrant(ctx, scope, route.group, subject)
		} else {
			granted, err = s.Roles.SubscriptionGrant(ctx, scope, subject)
		}
		if err != nil {
			unavailable(w)
			return false
		}
		if granted {
			return true
		}
	}
	if route.collection == "functionSite" && strings.Contains(strings.ToLower(route.name), "/functions/") && !read {
		action := "Microsoft.Web/sites/functions/keys/write"
		if r.Method == http.MethodPost {
			action = "Microsoft.Web/sites/functions/listKeys/action"
		}
		event := AuditEvent{Time: time.Now().UTC(), Actor: subject, Action: action, Target: r.URL.Path, Outcome: "Denied"}
		if err := s.Roles.RecordAudit(ctx, scope, event); err != nil {
			unavailable(w)
			return false
		}
	}
	if route.collection == "deployment" && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
		action := deploymentType + "/write"
		if _, op, ok := strings.Cut(route.name, "/"); ok {
			action = deploymentType + "/" + op + "/action"
		}
		if err := s.Roles.RecordAudit(ctx, scope, AuditEvent{Time: time.Now().UTC(), Actor: subject, Action: action,
			Target: r.URL.Path, Outcome: "Denied"}); err != nil {
			unavailable(w)
			return false
		}
	}
	if (r.Method == http.MethodPut || r.Method == http.MethodDelete) &&
		(route.collection == "groups" || route.collection == "roleassignments" || route.collection == "personalDesktop" || networkResource) {
		action := "Microsoft.Resources/subscriptions/resourceGroups/"
		if route.collection == "roleassignments" {
			action = "Microsoft.Authorization/roleAssignments/"
		}
		if route.collection == "personalDesktop" {
			action = DesktopType + "/"
		}
		if r.Method == http.MethodDelete {
			action += "delete"
		} else {
			action += "write"
		}
		if route.collection == "network" {
			path, _ := parseNetworkPath(route.name)
			action = networkAction(r.Method, path)
		}
		if route.collection == "securityGroup" {
			path, _ := parseSecurityGroupPath(route.name)
			action = securityGroupAction(r.Method, path)
		}
		if route.collection == "egress" {
			action = egressAction(r.Method, egressResourceType(strings.Split(route.name, "/")[1]))
		}
		if route.collection == "vpn" {
			kind, _ := vpnResourceType(strings.Split(route.name, "/")[1])
			action = egressAction(r.Method, kind)
		}
		event := AuditEvent{Time: time.Now().UTC(), Actor: subject, Action: action, Target: r.URL.Path, Outcome: "Denied"}
		if err := s.Roles.RecordAudit(ctx, scope, event); err != nil {
			unavailable(w)
			return false
		}
	}
	writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal has no permission at this scope.")
	return false
}

func (s Server) subscriptionPrincipal(ctx context.Context, w http.ResponseWriter, r *http.Request, subscription string) (identity.ARMPrincipal, bool) {
	principal, err := s.Authenticate(ctx, r)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidARMToken) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "A valid ARM access token is required.")
		} else {
			unavailable(w)
		}
		return identity.ARMPrincipal{}, false
	}
	if subscription != "" && !strings.EqualFold(principal.Subscription.SubscriptionID, subscription) {
		writeError(w, http.StatusNotFound, "SubscriptionNotFound", "The subscription could not be found.")
		return identity.ARMPrincipal{}, false
	}
	return principal, true
}

func readQuery(w http.ResponseWriter, r *http.Request, version string, parameterAllowed func(string, string) bool) (url.Values, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query string is invalid.")
		return nil, false
	}
	for key, items := range query {
		if len(items) != 1 || (key != "api-version" && (parameterAllowed == nil || !parameterAllowed(key, items[0]))) {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "The query contains an unsupported parameter or value.")
			return nil, false
		}
	}
	if query.Get("api-version") != version {
		writeError(w, http.StatusBadRequest, "InvalidApiVersionParameter", "This operation requires api-version="+version+".")
		return nil, false
	}
	return query, true
}

func methodNotAllowed(w http.ResponseWriter, methods string) {
	w.Header().Set("Allow", methods)
	writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "This method is unsupported at the requested scope.")
}

func unavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "ServiceUnavailable", "The regional resource store is unavailable.")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("x-ms-error-code", code)
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
