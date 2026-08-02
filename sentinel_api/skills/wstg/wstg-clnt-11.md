---
id: WSTG-CLNT-11
name: Testing Web Messaging
description: Auto-generated from OWASP WSTG (WSTG-CLNT-11).
confidence: medium
rationale: Evidence-driven mapping for Testing Web Messaging.
manual_only: false
wstg_ids: [WSTG-CLNT-11]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Assess the security of the message's origin.
  - Validate objective: Validate that it's using safe methods and validating its input.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Web_Messaging
