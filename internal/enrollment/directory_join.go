package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	StageDirectoryJoin = "stage-join"
	CloseDirectoryJoin = "close-join"
)

var (
	directoryJoinID       = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	directoryJoinMachine  = regexp.MustCompile(`^[A-Z0-9]([A-Z0-9-]{0,13}[A-Z0-9])?$`)
	directoryJoinLetter   = regexp.MustCompile(`[A-Z]`)
	directoryJoinPassword = regexp.MustCompile(`^[!-~]{32,128}$`)
)

func ValidDirectoryJoinID(id string) bool { return directoryJoinID.MatchString(id) }

// DirectoryJoinInput is delivered to exactly one directory writer.
type DirectoryJoinInput struct {
	ID        string `json:"requestId"`
	Machine   string `json:"machineName"`
	ExpiresAt int64  `json:"expiresAt"`
	Password  string `json:"password,omitempty"`
}

func (i DirectoryJoinInput) Valid(stage bool) bool {
	return ValidDirectoryJoinID(i.ID) && directoryJoinMachine.MatchString(i.Machine) &&
		directoryJoinLetter.MatchString(i.Machine) && i.ExpiresAt > 0 &&
		(stage && directoryJoinPassword.MatchString(i.Password) || !stage && i.Password == "")
}

func (i DirectoryJoinInput) Username() string {
	return "oj-" + strings.ReplaceAll(i.ID, "-", "")[:17]
}

type DirectoryJoinTask struct {
	Attempt string             `json:"attempt"`
	Command string             `json:"command"`
	Input   DirectoryJoinInput `json:"input"`
}

func (t DirectoryJoinTask) Valid() bool {
	return ValidDirectoryJoinID(t.Attempt) &&
		(t.Command == StageDirectoryJoin || t.Command == CloseDirectoryJoin) &&
		t.Input.Valid(t.Command == StageDirectoryJoin)
}

type DirectoryJoinResult struct {
	Attempt   string `json:"attempt"`
	Succeeded *bool  `json:"succeeded"`
}

type directoryJoinStore interface {
	HostDirectoryJoinTask(context.Context, string, []byte, string, string) (*DirectoryJoinTask, error)
	FinishDirectoryJoin(context.Context, string, []byte, string, string, DirectoryJoinResult) error
}

func (a *Authority) directoryJoinTask(w http.ResponseWriter, r *http.Request) {
	store, enabled := a.store.(directoryJoinStore)
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
	var task *DirectoryJoinTask
	var err error
	if r.Method == http.MethodGet {
		task, err = store.HostDirectoryJoinTask(ctx, host, peer.Raw, tenant, generation)
	} else {
		var result DirectoryJoinResult
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF ||
			!ValidDirectoryJoinID(result.Attempt) || result.Succeeded == nil {
			reject(w, http.StatusBadRequest, "InvalidDirectoryJoinResult")
			return
		}
		err = store.FinishDirectoryJoin(ctx, host, peer.Raw, tenant, generation, result)
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
