---
id: WSTG-INPV-18
name: Testing for Server-side Template Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-18).
confidence: high
rationale: Evidence-driven mapping for Testing for Server-side Template Injection.
manual_only: false
wstg_ids: [WSTG-INPV-18]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Detect template injection vulnerability points.
  - Validate objective: Identify the templating engine.
  - Validate objective: Build the exploit.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
