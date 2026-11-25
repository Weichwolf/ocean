package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("FUNCTIONS_CUSTOMHANDLER_PORT")
	if port == "" {
		log.Fatal("the Functions host did not supply a handler port")
	}
	handler := http.NewServeMux()
	handler.HandleFunc("GET /api/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "go:%s\n", os.Getenv("OCEAN_SETTING"))
	})
	server := http.Server{Addr: "127.0.0.1:" + port, Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	log.Fatal(server.ListenAndServe())
}
