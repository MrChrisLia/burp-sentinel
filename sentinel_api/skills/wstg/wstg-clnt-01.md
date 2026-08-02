---
id: WSTG-CLNT-01
name: Testing for DOM-Based Cross Site Scripting
description: Auto-generated from OWASP WSTG (WSTG-CLNT-01).
confidence: medium
rationale: Evidence-driven mapping for Testing for DOM-Based Cross Site Scripting.
manual_only: false
wstg_ids: [WSTG-CLNT-01]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Identify DOM sinks.
  - Validate objective: Build payloads that pertain to every sink type.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting
