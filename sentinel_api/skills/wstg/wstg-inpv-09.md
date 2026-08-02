---
id: WSTG-INPV-09
name: Testing for XPath Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-09).
confidence: high
rationale: Evidence-driven mapping for Testing for XPath Injection.
manual_only: false
wstg_ids: [WSTG-INPV-09]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify XPATH injection points.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_XPath_Injection
