---
id: WSTG-ERRH-02
name: Testing for Stack Traces
description: Auto-generated from OWASP WSTG (WSTG-ERRH-02).
confidence: medium
rationale: Evidence-driven mapping for Testing for Stack Traces.
manual_only: false
wstg_ids: [WSTG-ERRH-02]
triggers:
  status_codes: ["500", "502", "503", "504"]
tasks:
  - Execute focused tests for WSTG-ERRH-02 on relevant in-scope endpoints.
  - Capture concrete request/response evidence for pass/fail.
  - Document confidence and business impact of observed behavior.
---

Category: Testing for Error Handling (WSTG-ERRH)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/02-Testing_for_Stack_Traces
