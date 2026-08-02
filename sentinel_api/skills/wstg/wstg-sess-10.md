---
id: WSTG-SESS-10
name: Testing JSON Web Tokens
description: Auto-generated from OWASP WSTG (WSTG-SESS-10).
confidence: high
rationale: Evidence-driven mapping for Testing JSON Web Tokens.
manual_only: false
wstg_ids: [WSTG-SESS-10]
triggers:
  methods: ["POST", "PUT", "PATCH", "DELETE", "GET"]
  path_contains: ["/auth", "/login", "/logout", "/session", "/token", "/oauth", "/jwt"]
  query_params: ["token", "jwt"]
tasks:
  - Validate objective: Determine whether the JWTs expose sensitive information.
  - Validate objective: Determine whether the JWTs can be tampered with or modified.
---

Category: Session Management Testing (WSTG-SESS)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
