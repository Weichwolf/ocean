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

var ErrDirectoryUsersBusy = errors.New("the tenant directory is processing another user request")

type managedGraphUserStore interface {
	RunDirectoryUser(context.Context, TenantReservation, enrollment.DirectoryUserInput) (enrollment.DirectoryUserResult, error)
}

func (c *Compatibility) managedGraphUsers(ctx context.Context, w http.ResponseWriter, req *http.Request, tenant TenantReservation) bool {
	store, enabled := c.directories.(managedGraphUserStore)
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
	input, query, err := managedUserInput(w, req)
	if err != nil {
		graphError(w, http.StatusBadRequest, "Request_BadRequest", err.Error())
		return true
	}
	if input.Operation == "" {
		graphError(w, http.StatusMethodNotAllowed, "Request_UnsupportedOperation", "This operation is outside the managed user profile.")
		return true
	}
	result, err := store.RunDirectoryUser(ctx, tenant, input)
	switch {
	case errors.Is(err, ErrDirectoryUsersBusy):
		w.Header().Set("Retry-After", "2")
		graphError(w, http.StatusTooManyRequests, "TooManyRequests", ErrDirectoryUsersBusy.Error())
	case err != nil:
		graphUnavailable(w)
	case result.Status == http.StatusBadRequest:
		graphError(w, result.Status, "Request_BadRequest", "The directory rejected the managed user properties.")
	case result.Status == http.StatusConflict:
		graphError(w, result.Status, "Request_Conflict", "The user name or operation conflicts with the directory.")
	case result.Status == http.StatusNotFound:
		graphError(w, result.Status, "Request_ResourceNotFound", "The managed user was not found.")
	case input.Operation == enrollment.DirectoryUserList:
		users := result.Users
		if users == nil {
			users = []enrollment.DirectoryUserView{}
		}
		body := map[string]any{"value": users}
		if result.More {
			query.Set("$skip", strconv.Itoa(input.Query.Offset+enrollment.DirectoryUserPageSize))
			body["@odata.nextLink"] = c.cloud.MicrosoftGraph + "/v1.0/users?" + query.Encode()
		}
		writeJSON(w, result.Status, body)
	case result.Status == http.StatusNoContent:
		w.WriteHeader(result.Status)
	default:
		writeJSON(w, result.Status, result.User)
	}
	return true
}

func managedUserInput(w http.ResponseWriter, req *http.Request) (enrollment.DirectoryUserInput, url.Values, error) {
	input := enrollment.DirectoryUserInput{Selector: strings.ToLower(req.PathValue("user"))}
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
		input.Query = new(enrollment.DirectoryUserQuery)
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
