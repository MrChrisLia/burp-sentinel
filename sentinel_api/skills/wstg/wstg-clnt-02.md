---
id: WSTG-CLNT-02
name: Testing for JavaScript Execution
description: Auto-generated from OWASP WSTG (WSTG-CLNT-02).
confidence: medium
rationale: Evidence-driven mapping for Testing for JavaScript Execution.
manual_only: false
wstg_ids: [WSTG-CLNT-02]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Identify sinks and possible JavaScript injection points.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_JavaScript_Execution
