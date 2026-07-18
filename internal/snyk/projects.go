package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

const orgProjectsTimeout = 120 * time.Second

// collectOrgProjects reports the org's software inventory — every project Snyk
// monitors, whether it carries a dependency inventory (SBOM), and how recently
// it was scanned. Shape:
//
//	{ fetched_at, org_id,
//	  projects: [ { name, active, has_sbom, last_scan_age_days } ] }
//
// This backs the org_projects evidence type read by NIST CSF 2.0 ID.AM-02
// (software inventory). It uses the Snyk v1 projects endpoint because the REST
// projects list does not expose totalDependencies or lastTestedDate:
//   - active = the project is monitored,
//   - has_sbom = Snyk holds a dependency inventory for it (totalDependencies > 0),
//   - last_scan_age_days = whole days since the last test (omitted when the
//     project has never been tested, in which case has_sbom is already false).
func (c *Collector) collectOrgProjects(parent context.Context, ref plugin.EvidenceRef) (any, error) {
	orgID, err := requireStringParam(ref, "org_id")
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, orgProjectsTimeout)
	defer cancel()

	raw, err := c.getV1(ctx, "/v1/org/"+orgID+"/projects")
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	var page v1ProjectsPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, fmt.Errorf("parsing projects: %w", err)
	}

	projects := make([]map[string]any, 0, len(page.Projects))
	for _, p := range page.Projects {
		entry := map[string]any{
			"name":     p.Name,
			"active":   p.IsMonitored,
			"has_sbom": p.TotalDependencies > 0,
		}
		if age, ok := scanAgeDays(p.LastTestedDate); ok {
			entry["last_scan_age_days"] = age
		}
		projects = append(projects, entry)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"org_id":     orgID,
		"projects":   projects,
	}, nil
}

type v1ProjectsPage struct {
	Projects []v1Project `json:"projects"`
}

type v1Project struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	IsMonitored       bool   `json:"isMonitored"`
	TotalDependencies int    `json:"totalDependencies"`
	LastTestedDate    string `json:"lastTestedDate"`
}

// scanAgeDays returns whole days since the given RFC3339 timestamp. The second
// result is false when the timestamp is empty or unparseable (e.g. a project
// that has never been tested).
func scanAgeDays(ts string) (int, bool) {
	if ts == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return int(time.Since(t).Hours() / 24), true
}

// getV1 performs a GET against the Snyk v1 REST API, which returns
// application/json rather than the vnd.api+json envelope the newer REST API uses.
func (c *Collector) getV1(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("building snyk v1 request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("User-Agent", "concord-plugin-snyk/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing snyk v1 request %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading snyk v1 response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("snyk v1 %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}
