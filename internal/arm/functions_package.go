package arm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/functions"
)

type FunctionPackageDeployments interface {
	DeployFunctionZIP(context.Context, SubscriptionScope, string, string, []byte) (functions.DeploymentStatus, error)
	FunctionZIPStatus(context.Context, SubscriptionScope, string) (functions.DeploymentStatus, error)
}

func (s Server) functionSCMHost(host string) (string, bool) {
	if s.FunctionPackages == nil || s.AuthenticateSCM == nil {
		return "", false
	}
	return functions.SCMLabel(host, s.FunctionSCMDomain)
}

func (s Server) functionSCM(w http.ResponseWriter, r *http.Request, app string) {
	upload := r.URL.Path == "/api/zipdeploy"
	if !upload && r.URL.Path != "/api/deployments/latest" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	principal, ok := subscriptionPrincipal(ctx, w, r, "", s.AuthenticateSCM)
	if !ok {
		return
	}
	if !slices.Contains(principal.Subscription.Members, principal.Subject) {
		writeError(w, http.StatusForbidden, "AuthorizationFailed", "The principal cannot publish this Function App.")
		return
	}
	scope := SubscriptionScope{TenantID: principal.Subscription.TenantID, SubscriptionID: principal.Subscription.SubscriptionID}
	host := app + "." + s.FunctionDomain
	w.Header().Set("Cache-Control", "no-store")
	if !upload {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		if r.URL.RawQuery != "" {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameter", "Deployment status takes no query parameters.")
			return
		}
		status, err := s.FunctionPackages.FunctionZIPStatus(ctx, scope, host)
		if err != nil {
			containerError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, status)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 2 || len(query["isAsync"]) != 1 || query.Get("isAsync") != "true" ||
		len(query["Deployer"]) != 1 || query.Get("Deployer") != "az_cli_functions" ||
		r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Content-Encoding") != "" {
		writeError(w, http.StatusBadRequest, "InvalidDeployment", "Use the supported asynchronous Functions ZIP upload.")
		return
	}
	archive, err := io.ReadAll(http.MaxBytesReader(w, r.Body, functions.MaxZIPBytes))
	defer clear(archive)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeError(w, http.StatusRequestEntityTooLarge, "PackageTooLarge", functions.ErrZIPPackageTooLarge.Error())
		} else {
			writeError(w, http.StatusBadRequest, "InvalidDeployment", "The Functions ZIP body could not be read.")
		}
		return
	}
	result, err := s.FunctionPackages.DeployFunctionZIP(ctx, scope, principal.Subject, host, archive)
	switch {
	case errors.Is(err, functions.ErrZIPPackageTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "PackageTooLarge", functions.ErrZIPPackageTooLarge.Error())
	case errors.Is(err, functions.ErrInvalidZIPPackage):
		writeError(w, http.StatusBadRequest, "InvalidDeployment", functions.ErrInvalidZIPPackage.Error())
	case err != nil:
		containerError(w, err)
	default:
		w.Header().Set("Location", "/api/deployments/latest")
		writeJSON(w, http.StatusAccepted, result)
	}
}

func (s Server) functionSCMPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, address ResourceAddress) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if s.FunctionPackages == nil || s.FunctionSCMDomain == "" {
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The Functions SCM endpoint is disabled.")
		return
	}
	if s.getFunctionSite(ctx, w, scope, reader, address) != nil {
		writeJSON(w, http.StatusOK, map[string]any{"id": address.ID(scope) + "/basicPublishingCredentialsPolicies/scm",
			"name": "scm", "type": functions.SiteType + "/basicPublishingCredentialsPolicies",
			"properties": map[string]bool{"allow": false}})
	}
}

// The CLI attempts a log configuration write before presenting a failed ZIP
// deployment. Preserve the failure context while explicitly rejecting the write.
func (s Server) rejectFunctionLogConfiguration(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	reader string, address ResourceAddress) {
	message := "Functions log configuration is unsupported."
	if r.Method == http.MethodPut && s.FunctionPackages != nil {
		var input struct {
			Properties struct {
				ApplicationLogs *struct{} `json:"applicationLogs"`
				HTTPLogs        struct {
					Filesystem struct {
						Enabled       bool `json:"enabled"`
						RetentionDays int  `json:"retentionInDays"`
						RetentionMB   int  `json:"retentionInMb"`
					} `json:"fileSystem"`
				} `json:"httpLogs"`
			} `json:"properties"`
		}
		if err := strictJSON(http.MaxBytesReader(w, r.Body, 4096), &input); err == nil && input.Properties.ApplicationLogs != nil {
			logs := input.Properties.HTTPLogs.Filesystem
			if logs.Enabled && logs.RetentionDays == 3 && logs.RetentionMB == 100 {
				if s.getFunctionSite(ctx, w, scope, reader, address) == nil {
					return
				}
				name, _, _ := address.parts()
				deployment, err := s.FunctionPackages.FunctionZIPStatus(ctx, scope, name+"."+s.FunctionDomain)
				if err == nil && deployment.Status == functions.DeploymentFailed {
					message = "Zip deployment failed. " + deployment.Message + " " + message
				}
			}
		}
	}
	writeError(w, http.StatusBadRequest, "UnsupportedOperation", message)
}
