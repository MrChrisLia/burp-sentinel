---
id: WSTG-CLNT-04
name: Testing for Client-side URL Redirect
description: Auto-generated from OWASP WSTG (WSTG-CLNT-04).
confidence: medium
rationale: Evidence-driven mapping for Testing for Client-side URL Redirect.
manual_only: false
wstg_ids: [WSTG-CLNT-04]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
  query_params: ["redirect", "redirect_uri", "next", "url", "return", "return_to"]
  status_codes: ["301", "302", "303", "307", "308"]
tasks:
  - Validate objective: Identify injection points that handle URLs or paths.
  - Validate objective: Assess the locations that the system could redirect to.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
