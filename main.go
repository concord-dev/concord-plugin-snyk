package main

import (
	"net/http"
	"os"
	"time"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(&collector{
		baseURL:    envOr("SNYK_BASE_URL", defaultBaseURL),
		token:      os.Getenv("SNYK_TOKEN"),
		apiVersion: envOr("SNYK_API_VERSION", defaultAPIVersion),
		http:       &http.Client{Timeout: 60 * time.Second},
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
