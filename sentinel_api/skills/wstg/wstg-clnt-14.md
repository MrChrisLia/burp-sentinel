---
id: WSTG-CLNT-14
name: Testing for Reverse Tabnabbing
description: Auto-generated from OWASP WSTG (WSTG-CLNT-14).
confidence: medium
rationale: Evidence-driven mapping for Testing for Reverse Tabnabbing.
manual_only: false
wstg_ids: [WSTG-CLNT-14]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Execute focused tests for WSTG-CLNT-14 on relevant in-scope endpoints.
  - Capture concrete request/response evidence for pass/fail.
  - Document confidence and business impact of observed behavior.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Reverse_Tabnabbing
