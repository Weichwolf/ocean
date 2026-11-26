package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/desktop"
)

func TestNativeLeaseResponse(t *testing.T) {
	const machine = "db4fc27b-9f9f-459c-aae4-d926efc9277f"
	const account = "employee@ad.ocean.test"
	valid := desktop.NativeLease{MachineID: machine, AssignmentID: "dd906d95-9de5-49ef-b817-64f6cf85a976",
		UserID: "0d364785-fb10-4596-9575-a11b2ceb6535", Generation: "9098895f-14fc-4318-a71c-c82e6408c475",
		ExpiresAt: time.Now().Add(time.Hour)}
	for _, test := range []struct {
		name   string
		status int
		edit   func(*desktop.NativeLease)
	}{
		{name: "bounded lease", status: http.StatusOK},
		{name: "revoked", status: http.StatusForbidden},
		{name: "wrong VM", status: http.StatusOK, edit: func(l *desktop.NativeLease) { l.MachineID = l.AssignmentID }},
		{name: "expired lease", status: http.StatusOK, edit: func(l *desktop.NativeLease) { l.ExpiresAt = time.Now().Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			reply := valid
			if test.edit != nil {
				test.edit(&reply)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var input desktop.NativeAdmissionRequest
				if r.Method != http.MethodPost || r.URL.Path != desktop.NativeAdmissionPath || json.NewDecoder(r.Body).Decode(&input) != nil ||
					input != (desktop.NativeAdmissionRequest{User: account, Lease: true}) {
					t.Error("expected a native lease request for the current user")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(test.status)
				if test.status == http.StatusOK {
					if err := json.NewEncoder(w).Encode(reply); err != nil {
						t.Error(err)
					}
				}
			}))
			defer server.Close()
			lease, err := readNativeLease(t.Context(), server.Client(), server.URL, account, machine)
			switch {
			case test.status == http.StatusForbidden:
				if !errors.Is(err, errNativeDenied) {
					t.Fatalf("expected an explicit denial, got %v", err)
				}
			case test.edit != nil:
				if err == nil {
					t.Fatal("invalid native lease was accepted")
				}
			default:
				now := time.Now()
				if err != nil || !sameNativeAssignment(lease, valid) || !now.Before(lease.ExpiresAt) ||
					lease.ExpiresAt.After(now.Add(desktop.NativeLeaseLifetime)) {
					t.Fatalf("expected a locally bounded lease, got %+v: %v", lease, err)
				}
			}
		})
	}
}
