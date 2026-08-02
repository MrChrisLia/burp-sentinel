---
id: WSTG-ATHN-01
name: Testing for Credentials Transported over an Encrypted Channel
description: Auto-generated from OWASP WSTG (WSTG-ATHN-01).
confidence: high
rationale: Evidence-driven mapping for Testing for Credentials Transported over an Encrypted Channel.
manual_only: false
wstg_ids: [WSTG-ATHN-01]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Execute focused tests for WSTG-ATHN-01 on relevant in-scope endpoints.
  - Capture concrete request/response evidence for pass/fail.
  - Document confidence and business impact of observed behavior.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel
