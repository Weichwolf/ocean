package arm

import (
	"net/http"

	"github.com/Weichwolf/ocean/internal/functions"
)

const functionStacksPath = "/providers/Microsoft.Web/functionAppStacks"

func (s Server) functionStacks(w http.ResponseWriter, r *http.Request) {
	if !s.FunctionPlans {
		writeError(w, http.StatusNotFound, "InvalidResourceNamespace", "The provider namespace is unsupported.")
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if _, ok := readQuery(w, r, functions.APIVersion, nil); !ok {
		return
	}
	ctx := r.Context()
	if _, ok := s.subscriptionPrincipal(ctx, w, r, ""); !ok {
		return
	}
	stacks := []map[string]any{
		functionStack("java", "Java", "21"),
		functionStack("node", "Node.js", "22"),
		functionStack("dotnet-isolated", ".NET Isolated", "10.0"),
		functionStack("custom", "Custom handler", "1.0"),
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": stacks})
}

func functionStack(runtime, label, version string) map[string]any {
	runtimeSettings := map[string]any{
		"appInsightsSettings":                 map[string]bool{"isSupported": true},
		"appSettingsDictionary":               map[string]string{"FUNCTIONS_WORKER_RUNTIME": runtime},
		"gitHubActionSettings":                map[string]bool{"isSupported": false},
		"isDefault":                           true,
		"runtimeVersion":                      runtime + "|" + version,
		"siteConfigPropertiesDictionary":      map[string]bool{"use32BitWorkerProcess": false},
		"supportedFunctionsExtensionVersions": []string{"~4"},
	}
	label += " " + version
	minorVersion := map[string]any{"value": version, "displayText": label,
		"stackSettings": map[string]any{"linuxRuntimeSettings": runtimeSettings}}
	majorVersion := map[string]any{"value": version, "displayText": label, "minorVersions": []any{minorVersion}}
	return map[string]any{"name": runtime, "type": "Microsoft.Web/functionAppStacks", "id": functionStacksPath + "/" + runtime,
		"properties": map[string]any{"displayText": label, "value": runtime, "preferredOs": "Linux", "majorVersions": []any{majorVersion}}}
}
