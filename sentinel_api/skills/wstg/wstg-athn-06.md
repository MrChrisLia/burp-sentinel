---
id: WSTG-ATHN-06
name: Testing for Browser Cache Weaknesses
description: Auto-generated from OWASP WSTG (WSTG-ATHN-06).
confidence: high
rationale: Evidence-driven mapping for Testing for Browser Cache Weaknesses.
manual_only: false
wstg_ids: [WSTG-ATHN-06]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth"]
tasks:
  - Validate objective: Review if the application stores sensitive information on the client-side.
  - Validate objective: Review if access can occur without authorization.
---

Category: Authentication Testing (WSTG-ATHN)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses
