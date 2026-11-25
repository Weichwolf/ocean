package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

var graphGroupIdentityFilter = regexp.MustCompile(`^displayName eq '([^']+)' and mailNickname eq '([^']+)'$`)

func (c *Compatibility) graphGroup(w http.ResponseWriter, req *http.Request) {
	if !strings.EqualFold(req.Host, strings.TrimPrefix(c.cloud.MicrosoftGraph, "https://")) {
		http.NotFound(w, req)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 25*time.Second)
	defer cancel()
	tenant := c.graphTenant(ctx, w, req)
	if tenant != nil && !c.managedGraph(ctx, w, req, *tenant, true) {
		graphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The tenant has no managed domain.")
	}
}

type managedGroupFields struct {
	Name        string `json:"displayName"`
	Alias       string `json:"mailNickname"`
	Description string `json:"description,omitempty"`
	Mail        *bool  `json:"mailEnabled"`
	Security    *bool  `json:"securityEnabled"`
}

func managedGroupInput(w http.ResponseWriter, req *http.Request, origin string) (enrollment.DirectoryGraphInput, url.Values, error) {
	input := enrollment.DirectoryGraphInput{Selector: strings.ToLower(req.PathValue("group"))}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return input, nil, errors.New("invalid group query")
	}
	if input.Selector != "" && !enrollment.ValidDirectoryJoinID(input.Selector) {
		return input, nil, errors.New("use a group object UUID")
	}
	members := strings.HasSuffix(req.URL.Path, "/members")
	collection := input.Selector == ""
	if len(query) != 0 && (req.Method != http.MethodGet && req.Method != http.MethodHead || !members && !collection) {
		return input, nil, errors.New("unsupported group query parameter")
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		switch {
		case members, collection:
			input.Query, err = managedGroupQuery(query, members)
			if err != nil {
				return input, nil, err
			}
			input.Operation = enrollment.DirectoryGroupList
			if members {
				input.Operation = enrollment.DirectoryGroupMembers
			}
		default:
			input.Operation = enrollment.DirectoryGroupGet
		}
	case http.MethodPost:
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		if collection {
			var fields managedGroupFields
			if decoder.Decode(&fields) != nil || decoder.Decode(new(any)) != io.EOF || !validManagedGroupFields(fields) {
				return input, nil, errors.New("submit the display name and alias of a security group without mail delivery")
			}
			input.Fields, err = json.Marshal(fields)
			if err != nil {
				return input, nil, err
			}
			input.Operation = enrollment.DirectoryGroupCreate
			break
		}
		var reference struct {
			ID string `json:"@odata.id"`
		}
		if decoder.Decode(&reference) != nil || decoder.Decode(new(any)) != io.EOF {
			return input, nil, errors.New("submit one Graph directory object reference")
		}
		id, valid := strings.CutPrefix(reference.ID, origin+"/v1.0/directoryObjects/")
		if !valid {
			return input, nil, errors.New("the member reference must use the configured Graph origin")
		}
		input.Member = strings.ToLower(id)
		input.Operation = enrollment.DirectoryGroupMemberAdd
	case http.MethodDelete:
		if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, req.Body, 0)); err != nil {
			return input, nil, errors.New("removing a membership takes no request body")
		}
		input.Member = strings.ToLower(req.PathValue("member"))
		input.Operation = enrollment.DirectoryGroupMemberRemove
	}
	if !input.Valid() {
		return input, nil, errors.New("invalid managed group request")
	}
	return input, query, nil
}

func managedGroupQuery(query url.Values, members bool) (*enrollment.DirectoryGraphQuery, error) {
	result := new(enrollment.DirectoryGraphQuery)
	for name, values := range query {
		if len(values) != 1 || name != "$skip" && (name != "$filter" || members) {
			return nil, errors.New("unsupported group query parameter")
		}
	}
	if query.Has("$skip") {
		offset, err := strconv.Atoi(query.Get("$skip"))
		if err != nil {
			return nil, errors.New("invalid group page")
		}
		result.Offset = offset
	}
	if query.Has("$filter") {
		filter := query.Get("$filter")
		if parts := graphGroupIdentityFilter.FindStringSubmatch(filter); parts != nil {
			result.GroupName, result.GroupAlias = parts[1], parts[2]
		} else if parts := graphNameFilter.FindStringSubmatch(filter); parts != nil {
			result.DisplayPrefix = parts[1]
		} else {
			return nil, errors.New("unsupported group filter")
		}
	}
	return result, nil
}

func validManagedGroupFields(fields managedGroupFields) bool {
	return fields.Mail != nil && !*fields.Mail && fields.Security != nil && *fields.Security &&
		graphAlias.MatchString(fields.Alias) && strings.TrimSpace(fields.Name) != "" && len(fields.Name) <= 120 &&
		len(fields.Description) <= 256 && !strings.ContainsFunc(fields.Name+fields.Description, unicode.IsControl)
}
