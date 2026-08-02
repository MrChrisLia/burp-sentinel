---
id: WSTG-CLNT-09
name: Testing for Clickjacking
description: Auto-generated from OWASP WSTG (WSTG-CLNT-09).
confidence: medium
rationale: Evidence-driven mapping for Testing for Clickjacking.
manual_only: false
wstg_ids: [WSTG-CLNT-09]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Assess application vulnerability to clickjacking attacks.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking
