// Command concord-plugin-snyk serves the Snyk evidence collector over the
// Concord plugin protocol v1.
package main

import (
	"net/http"
	"os"
	"time"

	"github.com/concord-dev/concord-plugin-snyk/internal/snyk"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(snyk.New(
		envOr("SNYK_BASE_URL", snyk.DefaultBaseURL),
		os.Getenv("SNYK_TOKEN"),
		envOr("SNYK_API_VERSION", snyk.DefaultAPIVersion),
		&http.Client{Timeout: 60 * time.Second},
	))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
