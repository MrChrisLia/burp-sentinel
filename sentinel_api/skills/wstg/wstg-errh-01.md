---
id: WSTG-ERRH-01
name: Testing for Improper Error Handling
description: Auto-generated from OWASP WSTG (WSTG-ERRH-01).
confidence: medium
rationale: Evidence-driven mapping for Testing for Improper Error Handling.
manual_only: false
wstg_ids: [WSTG-ERRH-01]
triggers:
  status_codes: ["500", "502", "503", "504"]
tasks:
  - Validate objective: Identify existing error output.
  - Validate objective: Analyze the different output returned.
---

Category: Testing for Error Handling (WSTG-ERRH)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling
