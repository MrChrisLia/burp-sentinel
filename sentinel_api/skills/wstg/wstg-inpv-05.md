---
id: WSTG-INPV-05
name: Testing for SQL Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-05).
confidence: high
rationale: Evidence-driven mapping for Testing for SQL Injection.
manual_only: false
wstg_ids: [WSTG-INPV-05]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify SQL injection points.
  - Validate objective: Assess the severity of the injection and the level of access that can be achieved through it.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
