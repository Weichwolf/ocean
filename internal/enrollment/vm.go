package enrollment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Weichwolf/ocean/internal/workload"
)

type virtualMachineStore interface {
	HostVirtualMachineTasks(context.Context, string, []byte, string, bool) (workload.VMTaskPage, error)
	ReportVirtualMachine(context.Context, string, []byte, workload.VMReport) error
}

func (a *Authority) virtualMachineTasks(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(virtualMachineStore)
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
	page, err := store.HostVirtualMachineTasks(ctx, host, peer.Raw, params.Get("continuation"), r.Header.Get(workload.VMSuspensionHeader) == "1")
	defer func() {
		for _, task := range page.Tasks {
			clear(task.VolumeKey)
		}
	}()
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		replyWorkloadError(w, err)
		return
	}
	respond(w, http.StatusOK, page)
}

func (a *Authority) virtualMachineStatus(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(virtualMachineStore)
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
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var report workload.VMReport
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF ||
		!hostName.MatchString(report.ID) || !hostName.MatchString(report.TenantID) || !hostName.MatchString(report.SubscriptionID) ||
		!hostName.MatchString(report.Generation) || !hostName.MatchString(report.Revision) ||
		!report.ValidState() {
		reject(w, http.StatusBadRequest, "InvalidWorkloadStatus")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if err := store.ReportVirtualMachine(ctx, host, peer.Raw, report); err != nil {
		replyWorkloadError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
