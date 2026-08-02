---
id: WSTG-CLNT-06
name: Testing for Client-side Resource Manipulation
description: Auto-generated from OWASP WSTG (WSTG-CLNT-06).
confidence: medium
rationale: Evidence-driven mapping for Testing for Client-side Resource Manipulation.
manual_only: false
wstg_ids: [WSTG-CLNT-06]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Identify sinks with weak input validation.
  - Validate objective: Assess the impact of the resource manipulation.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/06-Testing_for_Client-side_Resource_Manipulation
