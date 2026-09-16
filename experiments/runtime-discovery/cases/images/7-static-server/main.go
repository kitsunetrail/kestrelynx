// Command server is the minimal, statically-linked HTTP server used by
// case 7a (debian:12-slim) and case 7b (distroless/static-debian12): it
// exists only to be a long-running process whose executable is not owned
// by any package database entry and links no shared library at all, so it
// has no external behavior beyond answering "ok".
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
