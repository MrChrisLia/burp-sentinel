---
id: WSTG-CLNT-12
name: Testing Browser Storage
description: Auto-generated from OWASP WSTG (WSTG-CLNT-12).
confidence: medium
rationale: Evidence-driven mapping for Testing Browser Storage.
manual_only: false
wstg_ids: [WSTG-CLNT-12]
triggers:
  path_contains: [".js", "/app", "/static", "/assets"]
tasks:
  - Validate objective: Determine whether the site is storing sensitive data in client-side storage.
  - Validate objective: The code handling of the storage objects should be examined for possibilities of injection attacks, such as utilizing unvalidated input or vulnerable libraries.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/12-Testing_Browser_Storage
