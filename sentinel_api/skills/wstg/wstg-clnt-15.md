---
id: WSTG-CLNT-15
name: Testing for Client-side Template Injection
description: Auto-generated from OWASP WSTG (WSTG-CLNT-15).
confidence: medium
rationale: Evidence-driven mapping for Testing for Client-side Template Injection.
manual_only: false
wstg_ids: [WSTG-CLNT-15]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  path_contains: [".js", "/app", "/static", "/assets"]
  query_params: ["q", "query", "search", "url", "path", "template", "message", "comment", "name"]
tasks:
  - Validate objective: Identify the client-side framework and its version used by the application.
  - Validate objective: Detect injection points where user input is reflected into the DOM and processed by the template engine.
  - Validate objective: Assess if the injection allows for arbitrary JavaScript execution (XSS) via the template syntax.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/15-Testing_for_Client-Side_Template_Injection
