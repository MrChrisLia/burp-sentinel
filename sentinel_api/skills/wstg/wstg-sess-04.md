---
id: WSTG-SESS-04
name: Testing for Exposed Session Variables
description: Auto-generated from OWASP WSTG (WSTG-SESS-04).
confidence: high
rationale: Evidence-driven mapping for Testing for Exposed Session Variables.
manual_only: false
wstg_ids: [WSTG-SESS-04]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Ensure that proper encryption is implemented.
  - Validate objective: Review the caching configuration.
  - Validate objective: Assess the channel and methods' security.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables
