package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const (
	DirectoryUserCreate        = "userCreate"
	DirectoryUserGet           = "userGet"
	DirectoryUserList          = "userList"
	DirectoryUserUpdate        = "userUpdate"
	DirectoryGroupCreate       = "groupCreate"
	DirectoryGroupGet          = "groupGet"
	DirectoryGroupList         = "groupList"
	DirectoryGroupMembers      = "groupMembers"
	DirectoryGroupMemberAdd    = "groupMemberAdd"
	DirectoryGroupMemberRemove = "groupMemberRemove"
	DirectoryGraphPageSize     = 100
	MaxDirectoryGraphResult    = 256 << 10
)

type DirectoryGraphQuery struct {
	UPN           string `json:"upn,omitempty"`
	DisplayPrefix string `json:"displayPrefix,omitempty"`
	GroupName     string `json:"groupName,omitempty"`
	GroupAlias    string `json:"groupAlias,omitempty"`
	Offset        int    `json:"offset,omitempty"`
}

type DirectoryGraphInput struct {
	Operation string               `json:"operation"`
	Selector  string               `json:"selector,omitempty"`
	Member    string               `json:"member,omitempty"`
	Fields    json.RawMessage      `json:"fields,omitempty"`
	Query     *DirectoryGraphQuery `json:"query,omitempty"`
}

func (i DirectoryGraphInput) Valid() bool {
	selector := i.Selector != "" && len(i.Selector) <= 128
	group := ValidDirectoryJoinID(i.Selector)
	fields := len(i.Fields) > 0 && len(i.Fields) <= 3200 && json.Valid(i.Fields)
	noFields := len(i.Fields) == 0
	q := i.Query
	paged := q != nil && q.Offset >= 0 && q.Offset <= 1000000
	if i.Member != "" && i.Operation != DirectoryGroupMemberAdd && i.Operation != DirectoryGroupMemberRemove {
		return false
	}
	switch i.Operation {
	case DirectoryUserCreate, DirectoryGroupCreate:
		return i.Selector == "" && fields && i.Query == nil
	case DirectoryUserUpdate:
		return selector && fields && i.Query == nil
	case DirectoryUserGet:
		return selector && noFields && i.Query == nil
	case DirectoryUserList:
		return i.Selector == "" && noFields && paged && q.GroupName == "" && q.GroupAlias == "" &&
			len(q.UPN) <= 128 && len(q.DisplayPrefix) <= 120 && (q.UPN == "" || q.DisplayPrefix == "" && q.Offset == 0)
	case DirectoryGroupGet:
		return group && noFields && q == nil
	case DirectoryGroupList:
		return i.Selector == "" && noFields && paged && q.UPN == "" && len(q.DisplayPrefix) <= 120 &&
			(q.GroupName == "" && q.GroupAlias == "" ||
				q.GroupName != "" && len(q.GroupName) <= 120 && q.GroupAlias != "" && len(q.GroupAlias) <= 64 && q.DisplayPrefix == "" && q.Offset == 0)
	case DirectoryGroupMembers:
		return group && noFields && paged && q.UPN == "" && q.DisplayPrefix == "" && q.GroupName == "" && q.GroupAlias == ""
	case DirectoryGroupMemberAdd, DirectoryGroupMemberRemove:
		return group && ValidDirectoryJoinID(i.Member) && noFields && q == nil
	}
	return false
}

func (i DirectoryGraphInput) Mutates() bool {
	switch i.Operation {
	case DirectoryUserCreate, DirectoryUserUpdate, DirectoryGroupCreate, DirectoryGroupMemberAdd, DirectoryGroupMemberRemove:
		return true
	}
	return false
}

type DirectoryGraphTask struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expiresAt"`
	DirectoryGraphInput
}

type DirectoryUserView struct {
	Kind        string `json:"@odata.type,omitempty"`
	ID          string `json:"id"`
	UPN         string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"mailNickname"`
	Enabled     bool   `json:"accountEnabled"`
	Mail        string `json:"mail"`
}

type DirectoryGroupView struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"mailNickname"`
	Description string `json:"description"`
	Security    bool   `json:"securityEnabled"`
	Mail        bool   `json:"mailEnabled"`
}

type DirectoryGraphResult struct {
	ID     string               `json:"id"`
	Status int                  `json:"status"`
	User   *DirectoryUserView   `json:"user,omitempty"`
	Users  []DirectoryUserView  `json:"users,omitempty"`
	Group  *DirectoryGroupView  `json:"group,omitempty"`
	Groups []DirectoryGroupView `json:"groups,omitempty"`
	More   bool                 `json:"more,omitempty"`
}

func (r DirectoryGraphResult) Valid(operation string) bool {
	count := len(r.Users) + len(r.Groups)
	if !ValidDirectoryJoinID(r.ID) || r.More && count != DirectoryGraphPageSize || count > DirectoryGraphPageSize {
		return false
	}
	valid := func(user DirectoryUserView) bool {
		return ValidDirectoryJoinID(user.ID) && len(user.UPN) <= 128 && user.UPN != "" && len(user.DisplayName) <= 120 &&
			len(user.Alias) <= 64 && len(user.Mail) <= 320 && (user.Kind == "" || user.Kind == "#microsoft.graph.user")
	}
	validGroup := func(group DirectoryGroupView) bool {
		return ValidDirectoryJoinID(group.ID) && group.DisplayName != "" && len(group.DisplayName) <= 120 &&
			group.Alias != "" && len(group.Alias) <= 64 && len(group.Description) <= 256 && group.Security && !group.Mail
	}
	if r.User != nil && !valid(*r.User) {
		return false
	}
	for _, user := range r.Users {
		if !valid(user) {
			return false
		}
	}
	if r.Group != nil && !validGroup(*r.Group) {
		return false
	}
	for _, group := range r.Groups {
		if !validGroup(group) {
			return false
		}
	}
	empty := r.User == nil && r.Group == nil && count == 0
	onlyUser := r.User != nil && r.Group == nil && count == 0
	onlyGroup := r.Group != nil && r.User == nil && count == 0
	collection := r.User == nil && r.Group == nil
	switch r.Status {
	case http.StatusBadRequest, http.StatusConflict, http.StatusNotFound:
		return empty
	case http.StatusCreated:
		return operation == DirectoryUserCreate && onlyUser || operation == DirectoryGroupCreate && onlyGroup
	case http.StatusNoContent:
		return empty && (operation == DirectoryUserUpdate || operation == DirectoryGroupMemberAdd || operation == DirectoryGroupMemberRemove)
	case http.StatusOK:
		return (operation == DirectoryUserList || operation == DirectoryGroupMembers) && collection && len(r.Groups) == 0 ||
			operation == DirectoryGroupList && collection && len(r.Users) == 0 ||
			operation == DirectoryUserGet && onlyUser || operation == DirectoryGroupGet && onlyGroup
	}
	return false
}

type directoryGraphTaskStore interface {
	HostDirectoryGraphTask(context.Context, string, []byte, string, string) (*DirectoryGraphTask, error)
	FinishDirectoryGraphTask(context.Context, string, []byte, string, string, DirectoryGraphResult) error
}

func (a *Authority) directoryGraphTask(w http.ResponseWriter, r *http.Request) {
	store, enabled := a.store.(directoryGraphTaskStore)
	host, tenant, generation := r.PathValue("host"), r.PathValue("tenant"), r.PathValue("generation")
	if !enabled || !hostName.MatchString(host) || !hostName.MatchString(tenant) ||
		!hostName.MatchString(generation) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	var task *DirectoryGraphTask
	var err error
	if r.Method == http.MethodGet {
		task, err = store.HostDirectoryGraphTask(ctx, host, peer.Raw, tenant, generation)
	} else {
		var result DirectoryGraphResult
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxDirectoryGraphResult))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || !ValidDirectoryJoinID(result.ID) {
			reject(w, http.StatusBadRequest, "InvalidDirectoryGraphResult")
			return
		}
		err = store.FinishDirectoryGraphTask(ctx, host, peer.Raw, tenant, generation, result)
	}
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrDirectoryAssignmentChanged):
		reject(w, http.StatusConflict, "DirectoryAssignmentChanged")
	case err != nil:
		reject(w, http.StatusServiceUnavailable, "DirectoryUnavailable")
	case task == nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(task)
	}
}
