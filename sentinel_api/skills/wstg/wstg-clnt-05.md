---
id: WSTG-CLNT-05
name: Testing for CSS Injection
description: Auto-generated from OWASP WSTG (WSTG-CLNT-05).
confidence: medium
rationale: Evidence-driven mapping for Testing for CSS Injection.
manual_only: false
wstg_ids: [WSTG-CLNT-05]
triggers:
  methods: ["GET", "POST"]
  path_contains: [".js", "/app", "/static", "/assets"]
  query_params: ["q", "search", "message", "comment", "name"]
tasks:
  - Validate objective: Identify CSS injection points.
  - Validate objective: Assess the impact of the injection.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection
