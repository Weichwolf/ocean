package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/Weichwolf/ocean/internal/workload"
)

var ErrWorkloadChanged = errors.New("workload placement or revision changed")

type workloadStore interface {
	HostContainerTasks(context.Context, string, []byte, string, bool) (workload.Page, error)
	ReportContainerTask(context.Context, string, []byte, workload.Report) error
}

func (a *Authority) containerTasks(w http.ResponseWriter, r *http.Request, networkOnly bool) {
	store, supported := a.store.(workloadStore)
	host := r.PathValue("host")
	if !supported || !hostName.MatchString(host) {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	params, err := url.ParseQuery(r.URL.RawQuery)
	cursor := params["continuation"]
	if err != nil || len(params) != 0 && (len(params) != 1 || len(cursor) != 1 || !validAssignmentCursor(cursor[0])) {
		reject(w, http.StatusBadRequest, "InvalidWorkloadQuery")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	page, err := store.HostContainerTasks(ctx, host, peer.Raw, params.Get("continuation"), networkOnly)
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		replyWorkloadError(w, err)
		return
	}
	respond(w, http.StatusOK, page)
}

func (a *Authority) containerStatus(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(workloadStore)
	host := r.PathValue("host")
	if !supported || !hostName.MatchString(host) || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	peer := verifiedHostCertificate(r)
	if peer == nil {
		reject(w, http.StatusUnauthorized, "HostCertificateRequired")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 100<<10))
	decoder.DisallowUnknownFields()
	var report workload.Report
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF ||
		!hostName.MatchString(report.ID) || !hostName.MatchString(report.TenantID) || !hostName.MatchString(report.SubscriptionID) ||
		!hostName.MatchString(report.Generation) || !hostName.MatchString(report.Revision) || len(report.Logs) > workload.MaxLogs ||
		!slices.Contains([]string{workload.Running, workload.Stopped, workload.Failed, workload.Removed}, report.State) {
		reject(w, http.StatusBadRequest, "InvalidWorkloadStatus")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if err := store.ReportContainerTask(ctx, host, peer.Raw, report); err != nil {
		replyWorkloadError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func replyWorkloadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrHostDenied):
		reject(w, http.StatusForbidden, "HostIdentityDenied")
	case errors.Is(err, ErrWorkloadChanged):
		reject(w, http.StatusConflict, "WorkloadAssignmentChanged")
	default:
		reject(w, http.StatusServiceUnavailable, "WorkloadAssignmentUnavailable")
	}
}
