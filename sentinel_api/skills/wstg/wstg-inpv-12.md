---
id: WSTG-INPV-12
name: Testing for Command Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-12).
confidence: high
rationale: Evidence-driven mapping for Testing for Command Injection.
manual_only: false
wstg_ids: [WSTG-INPV-12]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify and assess command injection points.
  - Validate objective: Bypass special characters and OS commands filter.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
