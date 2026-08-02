---
id: WSTG-INPV-06
name: Testing for LDAP Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-06).
confidence: high
rationale: Evidence-driven mapping for Testing for LDAP Injection.
manual_only: false
wstg_ids: [WSTG-INPV-06]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify LDAP injection points.
  - Validate objective: Assess the severity of the injection.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection
