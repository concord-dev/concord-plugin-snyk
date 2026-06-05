package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	plugin "github.com/concord-dev/concord/pkg/plugin"
)

var errMissingToken = errors.New("SNYK_TOKEN is not set")

const (
	defaultBaseURL    = "https://api.snyk.io"
	defaultAPIVersion = "2024-10-15"
	probeTimeout      = 15 * time.Second
	orgIssuesTimeout  = 120 * time.Second
	containerTimeout  = 180 * time.Second
)

type collector struct {
	baseURL    string
	token      string
	apiVersion string
	http       *http.Client
}

func (c *collector) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{
		Source:         "snyk",
		Version:        "v0.1.0",
		SupportedTypes: []string{"org_issues", "container_issues"},
		RequiredEnv:    []string{"SNYK_TOKEN"},
		OptionalEnv:    []string{"SNYK_BASE_URL", "SNYK_API_VERSION"},
		Permissions: plugin.Permissions{
			Network:    []string{"api.snyk.io"},
			Filesystem: "none",
		},
		DocsURL: "https://github.com/concord-dev/concord-plugin-snyk",
	}
}

func (c *collector) Probe(ctx context.Context) (string, error) {
	if c.token == "" {
		return "", errMissingToken
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if _, err := c.get(ctx, "/rest/self?version="+c.apiVersion); err != nil {
		return "", err
	}
	return "authenticated against " + c.baseURL, nil
}

func (c *collector) Collect(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	if c.token == "" {
		return nil, errMissingToken
	}
	switch ref.Type {
	case "org_issues":
		return c.collectOrgIssues(ctx, ref)
	case "container_issues":
		return c.collectContainerIssues(ctx, ref)
	case "":
		return nil, fmt.Errorf("snyk collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: type %q", plugin.ErrUnsupportedType, ref.Type)
	}
}

func (c *collector) collectOrgIssues(parent context.Context, ref plugin.EvidenceRef) (any, error) {
	orgID, err := requireStringParam(ref, "org_id")
	if err != nil {
		return nil, err
	}
	severities := stringParamOr(ref, "severities", "critical,high,medium,low")
	statusFilter := stringParamOr(ref, "status", "open")

	ctx, cancel := context.WithTimeout(parent, orgIssuesTimeout)
	defer cancel()

	issues, err := c.listOrgIssues(ctx, orgID, severities, statusFilter)
	if err != nil {
		return nil, fmt.Errorf("listing issues: %w", err)
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"org_id":     orgID,
		"issues":     issues,
		"summary":    summarize(issues),
	}, nil
}

func (c *collector) collectContainerIssues(parent context.Context, ref plugin.EvidenceRef) (any, error) {
	orgID, err := requireStringParam(ref, "org_id")
	if err != nil {
		return nil, err
	}
	projectType := stringParamOr(ref, "project_type", "container_image")
	severities := stringParamOr(ref, "severities", "critical,high,medium,low")
	statusFilter := stringParamOr(ref, "status", "open")

	ctx, cancel := context.WithTimeout(parent, containerTimeout)
	defer cancel()

	projects, err := c.listProjects(ctx, orgID, projectType)
	if err != nil {
		return nil, fmt.Errorf("listing %s projects: %w", projectType, err)
	}

	projectsOut := make([]map[string]any, 0, len(projects))
	allIssues := make([]map[string]any, 0)
	for _, p := range projects {
		issues, err := c.listProjectIssues(ctx, orgID, p.ID, severities, statusFilter)
		if err != nil {
			return nil, fmt.Errorf("listing issues for project %s (%s): %w", p.Attributes.Name, p.ID, err)
		}
		for _, i := range issues {
			i["project_id"] = p.ID
			i["project_name"] = p.Attributes.Name
			i["target_reference"] = p.Attributes.TargetReference
			allIssues = append(allIssues, i)
		}
		projectsOut = append(projectsOut, map[string]any{
			"id":               p.ID,
			"name":             p.Attributes.Name,
			"target_reference": p.Attributes.TargetReference,
			"issue_count":      len(issues),
		})
	}
	return map[string]any{
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
		"org_id":       orgID,
		"project_type": projectType,
		"projects":     projectsOut,
		"issues":       allIssues,
		"summary":      summarize(allIssues),
	}, nil
}

func (c *collector) listOrgIssues(ctx context.Context, orgID, severities, statusFilter string) ([]map[string]any, error) {
	q := url.Values{}
	q.Set("version", c.apiVersion)
	q.Set("limit", "100")
	q.Set("effective_severity_level", severities)
	q.Set("status", statusFilter)
	return c.iterateIssues(ctx, fmt.Sprintf("/rest/orgs/%s/issues?%s", url.PathEscape(orgID), q.Encode()))
}

func (c *collector) listProjectIssues(ctx context.Context, orgID, projectID, severities, statusFilter string) ([]map[string]any, error) {
	q := url.Values{}
	q.Set("version", c.apiVersion)
	q.Set("limit", "100")
	q.Set("effective_severity_level", severities)
	q.Set("status", statusFilter)
	q.Set("scan_item.id", projectID)
	q.Set("scan_item.type", "project")
	return c.iterateIssues(ctx, fmt.Sprintf("/rest/orgs/%s/issues?%s", url.PathEscape(orgID), q.Encode()))
}

func (c *collector) iterateIssues(ctx context.Context, path string) ([]map[string]any, error) {
	var out []map[string]any
	for path != "" {
		raw, err := c.get(ctx, path)
		if err != nil {
			return nil, err
		}
		var page issuesPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("parsing issues page: %w", err)
		}
		for _, d := range page.Data {
			out = append(out, normalizeIssue(d))
		}
		path = nextPath(page.Links.Next, c.baseURL)
	}
	return out, nil
}

func (c *collector) listProjects(ctx context.Context, orgID, projectType string) ([]project, error) {
	q := url.Values{}
	q.Set("version", c.apiVersion)
	q.Set("limit", "100")
	q.Set("types", projectType)
	path := fmt.Sprintf("/rest/orgs/%s/projects?%s", url.PathEscape(orgID), q.Encode())

	var projects []project
	for path != "" {
		raw, err := c.get(ctx, path)
		if err != nil {
			return nil, err
		}
		var page projectsPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("parsing projects page: %w", err)
		}
		projects = append(projects, page.Data...)
		path = nextPath(page.Links.Next, c.baseURL)
	}
	return projects, nil
}

type projectsPage struct {
	Data  []project `json:"data"`
	Links links     `json:"links"`
}

type project struct {
	ID         string       `json:"id"`
	Type       string       `json:"type"`
	Attributes projectAttrs `json:"attributes"`
}

type projectAttrs struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	TargetReference string `json:"target_reference"`
	Origin          string `json:"origin"`
}

type issuesPage struct {
	Data  []issue `json:"data"`
	Links links   `json:"links"`
}

type links struct {
	Next string `json:"next"`
}

type issue struct {
	ID         string     `json:"id"`
	Type       string     `json:"type"`
	Attributes issueAttrs `json:"attributes"`
}

type issueAttrs struct {
	Key                    string       `json:"key"`
	Title                  string       `json:"title"`
	Type                   string       `json:"type"`
	Status                 string       `json:"status"`
	EffectiveSeverityLevel string       `json:"effective_severity_level"`
	Coordinates            []coordinate `json:"coordinates"`
	CreatedAt              string       `json:"created_at"`
	UpdatedAt              string       `json:"updated_at"`
}

type coordinate struct {
	IsFixableManually bool             `json:"is_fixable_manually"`
	IsFixableSnyk     bool             `json:"is_fixable_snyk"`
	IsFixableUpstream bool             `json:"is_fixable_upstream"`
	IsPatchable       bool             `json:"is_patchable"`
	IsPinnable        bool             `json:"is_pinnable"`
	IsUpgradeable     bool             `json:"is_upgradeable"`
	Representations   []representation `json:"representations"`
}

type representation struct {
	Dependency dependency `json:"dependency"`
}

type dependency struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

func normalizeIssue(d issue) map[string]any {
	out := map[string]any{
		"id":         d.ID,
		"key":        d.Attributes.Key,
		"title":      d.Attributes.Title,
		"type":       d.Attributes.Type,
		"status":     d.Attributes.Status,
		"severity":   strings.ToLower(d.Attributes.EffectiveSeverityLevel),
		"created_at": d.Attributes.CreatedAt,
		"updated_at": d.Attributes.UpdatedAt,
	}
	if len(d.Attributes.Coordinates) == 0 {
		out["fixable"] = false
		return out
	}
	c := d.Attributes.Coordinates[0]
	out["fixable"] = c.IsFixableManually || c.IsFixableSnyk || c.IsFixableUpstream || c.IsUpgradeable || c.IsPatchable || c.IsPinnable
	if len(c.Representations) > 0 {
		dep := c.Representations[0].Dependency
		out["package_name"] = dep.PackageName
		out["package_version"] = dep.PackageVersion
	}
	return out
}

func summarize(issues []map[string]any) map[string]any {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, i := range issues {
		s, _ := i["severity"].(string)
		if _, ok := counts[s]; ok {
			counts[s]++
		}
	}
	return map[string]any{
		"critical": counts["critical"],
		"high":     counts["high"],
		"medium":   counts["medium"],
		"low":      counts["low"],
		"total":    len(issues),
	}
}

func nextPath(next, baseURL string) string {
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, baseURL) {
		return strings.TrimPrefix(next, baseURL)
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		if u, err := url.Parse(next); err == nil {
			if u.RawQuery != "" {
				return u.Path + "?" + u.RawQuery
			}
			return u.Path
		}
	}
	return next
}

func (c *collector) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("User-Agent", "concord-plugin-snyk/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("snyk %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

func requireStringParam(ref plugin.EvidenceRef, key string) (string, error) {
	v := plugin.StringParam(ref, key)
	if v == "" {
		return "", fmt.Errorf("missing required param %q", key)
	}
	return v, nil
}

func stringParamOr(ref plugin.EvidenceRef, key, fallback string) string {
	if v := plugin.StringParam(ref, key); v != "" {
		return v
	}
	return fallback
}
