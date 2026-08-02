---
id: WSTG-CLNT-07
name: Testing Cross Origin Resource Sharing
description: Auto-generated from OWASP WSTG (WSTG-CLNT-07).
confidence: medium
rationale: Evidence-driven mapping for Testing Cross Origin Resource Sharing.
manual_only: false
wstg_ids: [WSTG-CLNT-07]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Identify endpoints that implement CORS.
  - Validate objective: Ensure that the CORS configuration is secure or harmless.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
