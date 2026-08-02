---
id: SENTINEL-IDOR-001
name: IDOR/BOLA Deep Check
description: Prioritize object-level authorization checks on ID-like routes and parameters.
confidence: high
rationale: Object identifiers were observed in routes/parameters.
wstg_ids: [WSTG-ATHZ-04, WSTG-APIT-02]
triggers:
  path_contains: ["/users/", "/accounts/", "/projects/", "/orgs/", "/tenant"]
  methods: [GET, POST, PUT, PATCH, DELETE]
tasks:
  - Replay object access as a different user/tenant session.
  - Replace object IDs with unauthorized IDs and compare behavior.
  - Capture response diffs (status, data, ownership signals) as evidence.
---

Use for object authorization drift detection.
