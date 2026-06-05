# concord-plugin-snyk

Concord plugin for [Snyk](https://snyk.io). Collects vulnerability evidence
from Snyk's REST API for use in `concord check`.

## Evidence types

| `type:` | Returns |
|---|---|
| `org_issues` | All open issues across an org (with severity counts) |
| `container_issues` | Issues per container-image project (with `target_reference`) |

## Required env

- `SNYK_TOKEN` — a token with scope to read your org's issues + projects

## Optional env

- `SNYK_BASE_URL` — defaults to `https://api.snyk.io`
- `SNYK_API_VERSION` — defaults to `2024-10-15`

## Params

| Param | Default | Notes |
|---|---|---|
| `org_id` | _required_ | Snyk org UUID |
| `severities` | `critical,high,medium,low` | comma-separated |
| `status` | `open` | `open`, `resolved`, etc. |
| `project_type` | `container_image` | only used by `container_issues` |

## Install

```sh
make install        # builds and copies to ~/.concord/plugins/snyk/v0.1.0/
SNYK_TOKEN=... concord check --controls ./your-controls
```

## Protocol

Speaks Concord plugin protocol v1 — see `github.com/concord-dev/concord/proto/concord/plugin/v1`.
