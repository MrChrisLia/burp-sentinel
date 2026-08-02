---
id: WSTG-INPV-19
name: Testing for Server-Side Request Forgery
description: Auto-generated from OWASP WSTG (WSTG-INPV-19).
confidence: high
rationale: Evidence-driven mapping for Testing for Server-Side Request Forgery.
manual_only: false
wstg_ids: [WSTG-INPV-19]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify SSRF injection points.
  - Validate objective: Test if the injection points are exploitable.
  - Validate objective: Asses the severity of the vulnerability.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
