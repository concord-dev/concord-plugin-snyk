package snyk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-snyk/internal/snyk"
)

func TestCollectOrgProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/org/org-1/projects") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"projects":[
			{"id":"p1","name":"api-prod","isMonitored":true,"totalDependencies":42,"lastTestedDate":"2020-01-01T00:00:00Z"},
			{"id":"p2","name":"never-scanned","isMonitored":true,"totalDependencies":0}
		]}`))
	}))
	defer srv.Close()

	c := snyk.New(srv.URL, "token", "2024-10-15", &http.Client{})
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{
		Type:   "org_projects",
		Params: map[string]any{"org_id": "org-1"},
	})
	require.NoError(t, err)
	m := out.(map[string]any)

	projects := m["projects"].([]map[string]any)
	require.Len(t, projects, 2)

	scanned := projects[0]
	assert.Equal(t, "api-prod", scanned["name"])
	assert.Equal(t, true, scanned["active"])
	assert.Equal(t, true, scanned["has_sbom"], "totalDependencies>0 means Snyk holds an inventory")
	assert.Greater(t, scanned["last_scan_age_days"].(int), 0)

	never := projects[1]
	assert.Equal(t, false, never["has_sbom"], "no dependencies means no SBOM")
	_, hasAge := never["last_scan_age_days"]
	assert.False(t, hasAge, "a never-tested project reports no scan age")
}

func TestCollectOrgProjects_MissingOrgID(t *testing.T) {
	c := snyk.New("https://example.com", "token", "2024-10-15", &http.Client{})
	_, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "org_projects"})
	require.Error(t, err)
}
