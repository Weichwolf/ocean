package enrollment

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Weichwolf/ocean/internal/workload"
)

type functionPackageStore interface {
	HostFunctionPackage(context.Context, string, []byte, workload.AssignmentID) ([]byte, error)
}

func (a *Authority) functionPackage(w http.ResponseWriter, r *http.Request) {
	store, supported := a.store.(functionPackageStore)
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
	query, err := url.ParseQuery(r.URL.RawQuery)
	assignment := workload.AssignmentID{ID: r.PathValue("task"), TenantID: query.Get("tenant"),
		SubscriptionID: query.Get("subscription"), Generation: query.Get("generation"), Revision: query.Get("revision")}
	if err != nil || len(query) != 4 || len(query["tenant"]) != 1 || len(query["subscription"]) != 1 ||
		len(query["generation"]) != 1 || len(query["revision"]) != 1 || !hostName.MatchString(assignment.ID) ||
		!hostName.MatchString(assignment.TenantID) || !hostName.MatchString(assignment.SubscriptionID) ||
		!hostName.MatchString(assignment.Generation) || !hostName.MatchString(assignment.Revision) {
		reject(w, http.StatusBadRequest, "InvalidWorkloadQuery")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	archive, err := store.HostFunctionPackage(ctx, host, peer.Raw, assignment)
	defer clear(archive)
	if err != nil {
		replyWorkloadError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	_, _ = w.Write(archive)
}
