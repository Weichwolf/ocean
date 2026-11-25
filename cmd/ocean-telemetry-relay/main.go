// ocean-telemetry-relay forwards workload loopback OTLP to its private host socket.
package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Weichwolf/ocean/internal/telemetry"
)

func main() {
	transport := &http.Transport{
		ResponseHeaderTimeout: 5 * time.Second,
		MaxConnsPerHost:       4,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", "/relay/collector.sock")
		},
	}
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	slots := make(chan struct{}, 4)
	handler := http.NewServeMux()
	handler.HandleFunc("POST /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "collector busy", http.StatusTooManyRequests)
			return
		}
		if r.ContentLength > telemetry.MaxBody {
			http.Error(w, "trace payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://collector/v1/traces",
			http.MaxBytesReader(w, r.Body, telemetry.MaxBody))
		if err != nil {
			http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
			return
		}
		request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		request.Header.Set("Content-Encoding", r.Header.Get("Content-Encoding"))
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "collector unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = response.Body.Close() }()
		w.Header().Set("Content-Type", response.Header.Get("Content-Type"))
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(response.Body, 4096))
	})
	server := &http.Server{Addr: "127.0.0.1:4318", Handler: handler, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 4 * time.Second, WriteTimeout: 7 * time.Second, IdleTimeout: 8 * time.Second, MaxHeaderBytes: 4096}
	log.Fatal(server.ListenAndServe())
}
