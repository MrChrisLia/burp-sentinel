---
id: WSTG-SESS-01
name: Testing for Session Management Schema
description: Auto-generated from OWASP WSTG (WSTG-SESS-01).
confidence: high
rationale: Evidence-driven mapping for Testing for Session Management Schema.
manual_only: false
wstg_ids: [WSTG-SESS-01]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Gather session tokens, for the same user and for different users where possible.
  - Validate objective: Analyze and ensure that enough randomness exists to stop session forging attacks.
  - Validate objective: Modify cookies that are not signed and contain information that can be manipulated.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema
