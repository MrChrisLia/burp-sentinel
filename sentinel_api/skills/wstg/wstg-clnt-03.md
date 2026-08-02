---
id: WSTG-CLNT-03
name: Testing for HTML Injection
description: Auto-generated from OWASP WSTG (WSTG-CLNT-03).
confidence: medium
rationale: Evidence-driven mapping for Testing for HTML Injection.
manual_only: false
wstg_ids: [WSTG-CLNT-03]
triggers:
  methods: ["GET", "POST"]
  path_contains: [".js", "/app", "/static", "/assets"]
  query_params: ["q", "search", "message", "comment", "name"]
tasks:
  - Validate objective: Identify HTML injection points and assess the severity of the injected content.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/03-Testing_for_HTML_Injection
