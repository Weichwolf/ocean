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
	DirectoryUserCreate    = "userCreate"
	DirectoryUserGet       = "userGet"
	DirectoryUserList      = "userList"
	DirectoryUserUpdate    = "userUpdate"
	DirectoryUserPageSize  = 100
	MaxDirectoryUserResult = 128 << 10
)

type DirectoryUserQuery struct {
	UPN           string `json:"upn,omitempty"`
	DisplayPrefix string `json:"displayPrefix,omitempty"`
	Offset        int    `json:"offset,omitempty"`
}

type DirectoryUserInput struct {
	Operation string              `json:"operation"`
	Selector  string              `json:"selector,omitempty"`
	Fields    json.RawMessage     `json:"fields,omitempty"`
	Query     *DirectoryUserQuery `json:"query,omitempty"`
}

func (i DirectoryUserInput) Valid() bool {
	selector := i.Selector != "" && len(i.Selector) <= 128
	fields := len(i.Fields) > 0 && len(i.Fields) <= 3200 && json.Valid(i.Fields)
	switch i.Operation {
	case DirectoryUserCreate:
		return i.Selector == "" && fields && i.Query == nil
	case DirectoryUserUpdate:
		return selector && fields && i.Query == nil
	case DirectoryUserGet:
		return selector && len(i.Fields) == 0 && i.Query == nil
	case DirectoryUserList:
		q := i.Query
		return i.Selector == "" && len(i.Fields) == 0 && q != nil && q.Offset >= 0 && q.Offset <= 1000000 &&
			len(q.UPN) <= 128 && len(q.DisplayPrefix) <= 120 && (q.UPN == "" || q.DisplayPrefix == "" && q.Offset == 0)
	}
	return false
}

func (i DirectoryUserInput) Mutates() bool {
	return i.Operation == DirectoryUserCreate || i.Operation == DirectoryUserUpdate
}

type DirectoryUserTask struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expiresAt"`
	DirectoryUserInput
}

type DirectoryUserView struct {
	ID          string `json:"id"`
	UPN         string `json:"userPrincipalName"`
	DisplayName string `json:"displayName"`
	Alias       string `json:"mailNickname"`
	Enabled     bool   `json:"accountEnabled"`
	Mail        string `json:"mail"`
}

type DirectoryUserResult struct {
	ID     string              `json:"id"`
	Status int                 `json:"status"`
	User   *DirectoryUserView  `json:"user,omitempty"`
	Users  []DirectoryUserView `json:"users,omitempty"`
	More   bool                `json:"more,omitempty"`
}

func (r DirectoryUserResult) Valid(operation string) bool {
	if !ValidDirectoryJoinID(r.ID) || (r.More && len(r.Users) != DirectoryUserPageSize) || len(r.Users) > DirectoryUserPageSize {
		return false
	}
	valid := func(user DirectoryUserView) bool {
		return ValidDirectoryJoinID(user.ID) && len(user.UPN) <= 128 && user.UPN != "" && len(user.DisplayName) <= 120 &&
			len(user.Alias) <= 64 && len(user.Mail) <= 320
	}
	if r.User != nil && !valid(*r.User) {
		return false
	}
	for _, user := range r.Users {
		if !valid(user) {
			return false
		}
	}
	empty := r.User == nil && len(r.Users) == 0
	switch r.Status {
	case http.StatusBadRequest, http.StatusConflict, http.StatusNotFound:
		return empty
	case http.StatusCreated:
		return operation == DirectoryUserCreate && r.User != nil && len(r.Users) == 0
	case http.StatusNoContent:
		return operation == DirectoryUserUpdate && empty
	case http.StatusOK:
		return operation == DirectoryUserList && r.User == nil ||
			operation == DirectoryUserGet && r.User != nil && len(r.Users) == 0
	}
	return false
}

type directoryUserTaskStore interface {
	HostDirectoryUserTask(context.Context, string, []byte, string, string) (*DirectoryUserTask, error)
	FinishDirectoryUserTask(context.Context, string, []byte, string, string, DirectoryUserResult) error
}

func (a *Authority) directoryUserTask(w http.ResponseWriter, r *http.Request) {
	store, enabled := a.store.(directoryUserTaskStore)
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
	var task *DirectoryUserTask
	var err error
	if r.Method == http.MethodGet {
		task, err = store.HostDirectoryUserTask(ctx, host, peer.Raw, tenant, generation)
	} else {
		var result DirectoryUserResult
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxDirectoryUserResult))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || !ValidDirectoryJoinID(result.ID) {
			reject(w, http.StatusBadRequest, "InvalidDirectoryUserResult")
			return
		}
		err = store.FinishDirectoryUserTask(ctx, host, peer.Raw, tenant, generation, result)
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
