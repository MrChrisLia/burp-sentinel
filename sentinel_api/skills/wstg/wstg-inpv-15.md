---
id: WSTG-INPV-15
name: Testing for HTTP Response Splitting
description: Auto-generated from OWASP WSTG (WSTG-INPV-15).
confidence: high
rationale: Evidence-driven mapping for Testing for HTTP Response Splitting.
manual_only: true
wstg_ids: [WSTG-INPV-15]
triggers:
tasks:
  - Validate objective: Identify user-controlled input that is reflected into HTTP response headers.
  - Validate objective: Assess whether CR (`\r`) and LF (`\n`) characters can be injected into response headers.
  - Validate objective: Determine the potential impact of successful HTTP Response Splitting attacks, such as cache poisoning or client-side exploitation.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Response_Splitting
