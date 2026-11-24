package identity

import "net/http"

// CloudEndpoints are the public service endpoints advertised to Azure CLI.
type CloudEndpoints struct {
	ResourceManager string `json:"resourceManager"`
	MicrosoftGraph  string `json:"microsoftGraph"`
}

func (c *Compatibility) cloudMetadata(w http.ResponseWriter, r *http.Request) {
	const version = "2022-09-01"
	query := r.URL.Query()
	if len(query) != 1 || len(query["api-version"]) != 1 || query.Get("api-version") != version {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{
			"code":    "InvalidApiVersionParameter",
			"message": "Cloud endpoint discovery requires api-version=" + version + ".",
		}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":                     "ocean",
		"resourceManager":          c.cloud.ResourceManager,
		"microsoftGraphResourceId": c.cloud.MicrosoftGraph,
		"authentication": map[string]any{
			"loginEndpoint": c.authority,
			"audiences":     []string{c.cloud.ResourceManager},
		},
		"suffixes": map[string]string{},
	})
}
