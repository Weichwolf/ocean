package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

var ErrDirectoryGraphBusy = errors.New("the tenant directory is processing another Graph request")

type managedGraphStore interface {
	RunDirectoryGraph(context.Context, TenantReservation, enrollment.DirectoryGraphInput) (enrollment.DirectoryGraphResult, error)
}

func (c *Compatibility) managedGraph(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation, groups bool) bool {
	store, enabled := c.directories.(managedGraphStore)
	if !enabled {
		return false
	}
	directory, err := c.directories.LookupManagedDirectory(ctx, tenant)
	if err != nil {
		graphUnavailable(w)
		return true
	}
	if directory == nil {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if directory.ProvisionedAt.IsZero() || !directory.Controllers[0].Ready {
		graphUnavailable(w)
		return true
	}
	parse := managedUserInput
	resource := "user"
	if groups {
		resource = "group"
		parse = func(w http.ResponseWriter, req *http.Request) (enrollment.DirectoryGraphInput, url.Values, error) {
			return managedGroupInput(w, req, c.cloud.MicrosoftGraph)
		}
	}
	input, query, err := parse(w, req)
	if err != nil {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return true
	}
	if input.Operation == "" {
		graphError(w, http.StatusMethodNotAllowed, "Request_UnsupportedOperation", "This operation is outside the managed "+resource+" profile.")
		return true
	}
	result, err := store.RunDirectoryGraph(ctx, tenant, input)
	switch {
	case errors.Is(err, ErrDirectoryGraphBusy):
		w.Header().Set("Retry-After", "2")
		graphError(w, http.StatusTooManyRequests, "TooManyRequests", ErrDirectoryGraphBusy.Error())
	case err != nil:
		graphUnavailable(w)
	case result.Status == http.StatusBadRequest:
		graphError(w, result.Status, "Request_BadRequest", "The directory rejected the managed "+resource+" properties.")
	case result.Status == http.StatusConflict:
		graphError(w, result.Status, "Request_Conflict", "The "+resource+" name or operation conflicts with the directory.")
	case result.Status == http.StatusNotFound:
		graphError(w, result.Status, "Request_ResourceNotFound", "The managed "+resource+" was not found.")
	case input.Operation == enrollment.DirectoryGroupList:
		writeManagedGraphPage(w, c.cloud.MicrosoftGraph+req.URL.EscapedPath(), query, input.Query.Offset, result.Groups, result.More)
	case input.Operation == enrollment.DirectoryUserList || input.Operation == enrollment.DirectoryGroupMembers:
		writeManagedGraphPage(w, c.cloud.MicrosoftGraph+req.URL.EscapedPath(), query, input.Query.Offset, result.Users, result.More)
	case result.Status == http.StatusNoContent:
		w.WriteHeader(result.Status)
	case groups:
		writeJSON(w, result.Status, result.Group)
	default:
		writeJSON(w, result.Status, result.User)
	}
	return true
}

func writeManagedGraphPage[T any](w http.ResponseWriter, path string, query url.Values, offset int, entries []T, more bool) {
	if entries == nil {
		entries = []T{}
	}
	body := map[string]any{"value": entries}
	if more {
		query.Set("$skip", strconv.Itoa(offset+enrollment.DirectoryGraphPageSize))
		body["@odata.nextLink"] = path + "?" + query.Encode()
	}
	writeJSON(w, http.StatusOK, body)
}

func managedUserInput(w http.ResponseWriter, req *http.Request) (enrollment.DirectoryGraphInput, url.Values, error) {
	input := enrollment.DirectoryGraphInput{Selector: strings.ToLower(req.PathValue("user"))}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return input, nil, errors.New("invalid directory query")
	}
	if len(query) != 0 && (req.Method != http.MethodGet && req.Method != http.MethodHead || input.Selector != "") {
		return input, nil, errors.New("unsupported directory query parameter")
	}
	if input.Selector != "" && !tenantID.MatchString(input.Selector) && !validGraphUPN(input.Selector) {
		return input, nil, errors.New("use a user principal name or object UUID")
	}
	switch req.Method {
	case http.MethodPost, http.MethodPatch:
		create := req.Method == http.MethodPost
		fields, err := readGraphUser(req, w, create)
		if err != nil {
			return input, nil, err
		}
		input.Fields, err = json.Marshal(fields)
		input.Operation = enrollment.DirectoryUserUpdate
		if create {
			input.Operation = enrollment.DirectoryUserCreate
		}
		return input, nil, err
	case http.MethodGet, http.MethodHead:
		if input.Selector != "" {
			input.Operation = enrollment.DirectoryUserGet
			break
		}
		input.Operation = enrollment.DirectoryUserList
		input.Query = new(enrollment.DirectoryGraphQuery)
		for name, values := range query {
			if len(values) != 1 || (name != "$filter" && name != "$skip") {
				return input, nil, errors.New("unsupported directory query parameter")
			}
		}
		if query.Has("$skip") {
			input.Query.Offset, err = strconv.Atoi(query.Get("$skip"))
			if err != nil {
				return input, nil, errors.New("invalid directory page")
			}
		}
		if query.Has("$filter") {
			filter := query.Get("$filter")
			switch {
			case graphUPNFilter.MatchString(filter):
				input.Query.UPN = strings.ToLower(graphUPNFilter.FindStringSubmatch(filter)[1])
				if !validGraphUPN(input.Query.UPN) {
					return input, nil, errors.New("invalid user principal name")
				}
			case graphNameFilter.MatchString(filter):
				input.Query.DisplayPrefix = graphNameFilter.FindStringSubmatch(filter)[1]
			default:
				return input, nil, errors.New("unsupported directory filter")
			}
		}
	}
	if input.Operation != "" && !input.Valid() {
		return input, nil, errors.New("invalid managed user query")
	}
	return input, query, nil
}
