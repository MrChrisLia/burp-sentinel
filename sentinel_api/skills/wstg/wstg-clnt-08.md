---
id: WSTG-CLNT-08
name: Testing for Cross Site Flashing
description: Auto-generated from OWASP WSTG (WSTG-CLNT-08).
confidence: medium
rationale: Evidence-driven mapping for Testing for Cross Site Flashing.
manual_only: false
wstg_ids: [WSTG-CLNT-08]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Decompile and analyze the application's code.
  - Validate objective: Assess sinks inputs and unsafe method usages.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/08-Testing_for_Cross_Site_Flashing
