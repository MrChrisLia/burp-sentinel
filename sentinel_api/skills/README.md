# Sentinel Markdown Skills

Sentinel can load custom skills from Markdown files in this directory.

Default directory:

- `/app/sentinel_api/skills` inside Docker
- `/Users/christopher/SentinelWorkspace/Projects/Sentinel Burpsuite Agent/sentinel_api/skills` on host

Override path with:

- `SENTINEL_SKILLS_DIR=/some/path`

## Skill File Format

Each `*.md` file must start with YAML frontmatter:

```md
---
id: SENTINEL-CUSTOM-001
name: Admin Export Abuse Checks
description: Prioritize authz testing on export/admin routes.
confidence: medium
rationale: Export/admin routes were observed.
wstg_ids: [WSTG-ATHZ-04, WSTG-APIT-02]
triggers:
  methods: [GET, POST]
  path_contains: ["/admin", "/export"]
  query_params: [id, tenant_id]
  status_codes: [200, 302]
  js_finding_types: [endpoint, secret, obfuscation]
  js_categories: [hidden_sensitive_endpoint]
  route_types: [graphql, websocket, sensitive]
  route_contains: ["/internal", "/graphql"]
  requires_auth: true
tasks:
  - Replay endpoint as lower-privileged role.
  - Swap IDs and compare object ownership.
  - Record differential responses and authorization decisions.
---

# Optional Notes

Freeform markdown notes can go here.
```

## Notes

- `id` + `name` are required.
- Trigger groups are ANDed when present.
- Within each trigger list, matching is OR.
- Matched custom skills are merged into WSTG recommendations and quest generation.
