---
id: WSTG-INPV-11
name: Testing for Code Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-11).
confidence: high
rationale: Evidence-driven mapping for Testing for Code Injection.
manual_only: false
wstg_ids: [WSTG-INPV-11]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify injection points where you can inject code into the application.
  - Validate objective: Assess the injection severity.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection
