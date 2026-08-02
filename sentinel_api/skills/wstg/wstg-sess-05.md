---
id: WSTG-SESS-05
name: Testing for Cross Site Request Forgery
description: Auto-generated from OWASP WSTG (WSTG-SESS-05).
confidence: high
rationale: Evidence-driven mapping for Testing for Cross Site Request Forgery.
manual_only: false
wstg_ids: [WSTG-SESS-05]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Determine whether it is possible to initiate requests on a user's behalf that are not initiated by the user.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery
