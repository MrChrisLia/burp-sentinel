---
id: WSTG-SESS-02
name: Testing for Cookies Attributes
description: Auto-generated from OWASP WSTG (WSTG-SESS-02).
confidence: high
rationale: Evidence-driven mapping for Testing for Cookies Attributes.
manual_only: false
wstg_ids: [WSTG-SESS-02]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Ensure that the proper security configuration is set for cookies.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
