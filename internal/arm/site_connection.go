package arm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Weichwolf/ocean/internal/network"
)

var ErrSiteConnectionInUse = errors.New("a site connection already uses this name or subnet")

type SiteConnectionRequest struct {
	Address    ResourceAddress
	Subnet     ResourceAddress
	Location   string
	Tags       map[string]string
	Properties network.SiteConnectionProperties
}

type SiteConnectionStore interface {
	CreateSiteConnection(context.Context, SubscriptionScope, string, SiteConnectionRequest) (InventoryResource, *Operation, bool, error)
	DeleteSiteConnection(context.Context, SubscriptionScope, string, ResourceAddress) (*Operation, error)
}

func readSiteConnection(body io.Reader, scope SubscriptionScope, address ResourceAddress, location string) (SiteConnectionRequest, error) {
	var input struct {
		Location   string                           `json:"location"`
		Tags       map[string]string                `json:"tags"`
		Properties network.SiteConnectionProperties `json:"properties"`
	}
	if err := strictJSON(body, &input); err != nil || input.Location != location || !validTags(input.Tags) {
		return SiteConnectionRequest{}, errors.New("the site connection requires the regional location and supported properties")
	}
	if err := input.Properties.Validate(); err != nil {
		return SiteConnectionRequest{}, err
	}
	subnet, ok := NetworkResourceAddress(scope, input.Properties.Subnet.ID, network.SubnetType)
	if !ok || !strings.EqualFold(subnet.Group, address.Group) {
		return SiteConnectionRequest{}, errors.New("the site connection subnet must be in its own resource group")
	}
	return SiteConnectionRequest{Address: address, Subnet: subnet, Location: location, Tags: input.Tags, Properties: input.Properties}, nil
}

func (s Server) siteConnection(ctx context.Context, w http.ResponseWriter, r *http.Request, scope SubscriptionScope,
	actor, reader, group, path string) {
	parts := strings.Split(path, "/")
	if len(parts) != 3 || !network.ValidName(parts[2]) {
		writeError(w, http.StatusBadRequest, "InvalidResourceId", "The site connection identifier is invalid.")
		return
	}
	if _, ok := readQuery(w, r, network.SiteConnectionAPIVersion, nil); !ok {
		return
	}
	address := ResourceAddress{Group: group, Path: network.SiteConnectionType + "/" + parts[2]}
	switch r.Method {
	case http.MethodGet:
		connection, err := s.Inventory.GetInventoryResource(ctx, scope, reader, address)
		if err != nil {
			inventoryError(w, err)
		} else if connection == nil {
			writeError(w, http.StatusNotFound, "ResourceNotFound", "The site connection does not exist.")
		} else {
			writeJSON(w, http.StatusOK, connection.view(scope))
		}
	case http.MethodPut:
		if s.SiteConnections == nil {
			unavailable(w)
			return
		}
		desired, err := readSiteConnection(http.MaxBytesReader(w, r.Body, 16<<10), scope, address, s.Location)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidRequestContent", err.Error())
			return
		}
		resource, operation, created, err := s.SiteConnections.CreateSiteConnection(ctx, scope, actor, desired)
		if err != nil {
			deploymentError(w, err)
		} else if operation == nil {
			writeJSON(w, createdStatus(created), resource.view(scope))
		} else {
			query := "?api-version=" + resourceAPIVersion
			w.Header().Set("Azure-AsyncOperation", s.Origin+operationPath(scope, "operationStatuses", operation.ID)+query)
			w.Header().Set("Location", s.Origin+address.ID(scope)+"?api-version="+network.SiteConnectionAPIVersion)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusAccepted, resource.view(scope))
		}
	case http.MethodDelete:
		if s.SiteConnections == nil {
			unavailable(w)
			return
		}
		operation, err := s.SiteConnections.DeleteSiteConnection(ctx, scope, actor, address)
		if err != nil {
			deploymentError(w, err)
		} else if operation == nil {
			w.WriteHeader(http.StatusNoContent)
		} else {
			s.acceptOperation(w, scope, *operation)
		}
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}
