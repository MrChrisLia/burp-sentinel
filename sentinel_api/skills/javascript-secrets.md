---
id: SENTINEL-JS-SECRET-001
name: JavaScript Secret Exposure Drill
description: Validate and triage potential credential/key exposure in JavaScript bundles.
confidence: high
rationale: JavaScript findings include secret-like material.
wstg_ids: [WSTG-INFO-05, WSTG-CLNT-02]
triggers:
  js_finding_types: [secret]
tasks:
  - Validate whether each detected secret is active and scoped.
  - Check if leaked keys grant backend or third-party API access.
  - Revoke/rotate confirmed active credentials and document impact.
---

Use when Sentinel detects potential hardcoded keys/tokens/secrets from JavaScript responses.
