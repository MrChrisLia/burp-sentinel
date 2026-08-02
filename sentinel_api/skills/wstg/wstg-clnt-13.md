---
id: WSTG-CLNT-13
name: Testing for Cross Site Script Inclusion
description: Auto-generated from OWASP WSTG (WSTG-CLNT-13).
confidence: medium
rationale: Evidence-driven mapping for Testing for Cross Site Script Inclusion.
manual_only: false
wstg_ids: [WSTG-CLNT-13]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Locate sensitive data across the system.
  - Validate objective: Assess the leakage of sensitive data through various techniques.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion
