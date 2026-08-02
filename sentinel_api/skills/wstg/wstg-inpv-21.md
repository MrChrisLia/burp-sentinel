---
id: WSTG-INPV-21
name: Testing for CSV Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-21).
confidence: high
rationale: Evidence-driven mapping for Testing for CSV Injection.
manual_only: false
wstg_ids: [WSTG-INPV-21]
triggers:
  path_contains: ["/download", "/export", "/file", "/files"]
tasks:
  - Validate objective: Identify CSV/spreadsheet export features that include untrusted input.
  - Validate objective: Verify whether attacker-controlled values are interpreted as formulas when the export is opened in common spreadsheet applications.
  - Validate objective: Check whether separator/quote injection can move a dangerous prefix to the start of a cell.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_CSV_Injection
