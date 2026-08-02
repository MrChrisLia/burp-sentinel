---
id: WSTG-INPV-07
name: Testing for XML Injection
description: Auto-generated from OWASP WSTG (WSTG-INPV-07).
confidence: high
rationale: Evidence-driven mapping for Testing for XML Injection.
manual_only: false
wstg_ids: [WSTG-INPV-07]
triggers:
  methods: ["GET", "POST", "PUT", "PATCH"]
  query_params: ["q", "query", "search", "url", "path", "template"]
tasks:
  - Validate objective: Identify XML injection points.
  - Validate objective: Assess the types of exploits that can be attained and their severities.
---

Category: Input Validation Testing (WSTG-INPV)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
