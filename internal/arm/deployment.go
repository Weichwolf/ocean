package arm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const deploymentAPIVersion = "2025-04-01"
const deploymentType = "Microsoft.Resources/deployments"

var deploymentName = regexp.MustCompile(`^[A-Za-z0-9_.()-]{1,64}$`)

type NetworkDeploymentStore interface {
	DeployNetwork(context.Context, SubscriptionScope, string, NetworkDeployment, bool) (NetworkDeploymentPlan, bool, error)
}

type deploymentInput struct {
	Properties struct {
		Template        json.RawMessage          `json:"template"`
		Parameters      map[string]templateValue `json:"parameters"`
		Mode            string                   `json:"mode"`
		ValidationLevel string                   `json:"validationLevel"`
		WhatIfSettings  *struct {
			ResultFormat string `json:"resultFormat"`
		} `json:"whatIfSettings"`
	} `json:"properties"`
}

// InvalidDeployment is a rejected set of desired network resources.
type InvalidDeployment struct{ Cause error }

func (e InvalidDeployment) Error() string { return e.Cause.Error() }
func (e InvalidDeployment) Unwrap() error { return e.Cause }

func (s Server) deployment(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope, actor, reader, group, path string) {
	name, operation, _ := strings.Cut(path, "/")
	if !deploymentName.MatchString(name) || operation != "" && operation != "whatif" && operation != "validate" {
		writeError(w, http.StatusBadRequest, "InvalidDeployment", "The deployment name or operation is unsupported.")
		return
	}
	version := deploymentAPIVersion
	applicationGateway := s.GatewayDeployments != nil && r.URL.Query().Get("api-version") == ApplicationGatewayDeploymentVersion
	if applicationGateway {
		version = ApplicationGatewayDeploymentVersion
	}
	if _, ok := readQuery(w, r, version, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: deploymentType + "/" + name}
	if !address.Valid() {
		writeError(w, http.StatusBadRequest, "InvalidDeployment", "The deployment name is not supported.")
		return
	}
	if operation == "" && r.Method == http.MethodGet {
		resource, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
			return
		}
		if resource == nil || applicationGateway && resource.APIVersion != version {
			writeError(w, http.StatusNotFound, "DeploymentNotFound", "The deployment does not exist.")
			return
		}
		writeJSON(w, http.StatusOK, resource.view(scope))
		return
	}
	method := "GET, PUT"
	if operation != "" {
		method = "POST"
	}
	commit := operation == "" && r.Method == http.MethodPut
	if !commit && (operation == "" || r.Method != http.MethodPost) {
		methodNotAllowed(w, method)
		return
	}
	var input deploymentInput
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil || strictJSON(bytes.NewReader(quoteTemplateKey(body)), &input) != nil {
		writeError(w, http.StatusBadRequest, "InvalidTemplate", "The deployment request is not a supported inline template.")
		return
	}
	properties := input.Properties
	if applicationGateway {
		if operation == "whatif" || properties.WhatIfSettings != nil ||
			!strings.EqualFold(properties.Mode, "Incremental") || properties.ValidationLevel != "" && properties.ValidationLevel != "Provider" {
			writeError(w, http.StatusBadRequest, "InvalidDeployment", "Use an incremental HTTPS Application Gateway deployment.")
			return
		}
		s.applicationGatewayDeployment(ctx, w, scope, actor, address, input, commit)
		return
	}
	format := "FullResourcePayloads"
	if properties.WhatIfSettings != nil {
		format = properties.WhatIfSettings.ResultFormat
	}
	if properties.Mode != "Incremental" || properties.ValidationLevel != "" && properties.ValidationLevel != "Provider" ||
		properties.WhatIfSettings != nil && (operation != "whatif" || format != "FullResourcePayloads" && format != "ResourceIdOnly") {
		writeError(w, http.StatusBadRequest, "InvalidDeployment", "Use incremental deployment and the supported provider validation options.")
		return
	}
	desired, err := compileNetworkTemplate(scope, address, s.Location, properties.Template, properties.Parameters)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidTemplate", err.Error())
		return
	}
	plan, created, err := s.Deployments.DeployNetwork(ctx, scope, actor, desired, commit)
	if err != nil {
		deploymentError(w, err)
		return
	}
	last := plan.Resources[len(plan.Resources)-1]
	switch operation {
	case "whatif":
		if format == "ResourceIdOnly" {
			for index := range plan.changes {
				plan.changes[index].Before, plan.changes[index].After = nil, nil
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "Succeeded", "changes": plan.changes})
	case "validate":
		writeJSON(w, http.StatusOK, last.view(scope))
	default:
		writeJSON(w, createdStatus(created), last.view(scope))
	}
}

// Azure CLI 2.93.0 splices the inline template into the serialized body
// using an unquoted template key. All other keys and values use strict JSON.
func quoteTemplateKey(body []byte) []byte {
	const key = "template:"
	var previous byte
	quoted, escaped := false, false
	depth := 0
	for index, char := range body {
		if quoted {
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				quoted = false
				previous = char
			}
			continue
		}
		if depth == 2 && (previous == '{' || previous == ',') && char == 't' && bytes.HasPrefix(body[index:], []byte(key)) {
			return bytes.Join([][]byte{body[:index], []byte(`"template":`), body[index+len(key):]}, nil)
		}
		switch char {
		case '"':
			quoted = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ' ', '\t', '\n', '\r':
			continue
		}
		previous = char
	}
	return body
}

func deploymentError(w http.ResponseWriter, err error) {
	var invalid InvalidDeployment
	switch {
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, "InvalidTemplate", err.Error())
	case errors.Is(err, ErrLinkedResourceMissing):
		writeError(w, http.StatusBadRequest, "InvalidResourceReference", err.Error())
	case errors.Is(err, ErrPublicIPInUse):
		writeError(w, http.StatusConflict, "PublicIPAddressInUse", err.Error())
	case errors.Is(err, ErrPublicIPPoolExhausted):
		writeError(w, http.StatusConflict, "PublicIPPoolExhausted", err.Error())
	case errors.Is(err, ErrPublicIPPoolDisabled):
		writeError(w, http.StatusServiceUnavailable, "PublicIPPoolUnavailable", err.Error())
	case errors.Is(err, ErrGroupDeleting):
		writeError(w, http.StatusConflict, "ResourceGroupBeingDeleted", "The resource group is being deleted.")
	case errors.Is(err, ErrSubnetInUse):
		writeError(w, http.StatusConflict, "SubnetInUse", err.Error())
	case errors.Is(err, ErrGatewayExecutionUnavailable):
		writeError(w, http.StatusServiceUnavailable, "GatewayExecutionUnavailable", err.Error())
	default:
		inventoryError(w, err)
	}
}
