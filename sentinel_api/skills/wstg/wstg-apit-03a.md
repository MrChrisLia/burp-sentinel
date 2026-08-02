---
id: WSTG-APIT-03A
name: API Excessive Data Exposure
description: Companion skill for WSTG-APIT-03 (duplicate ID in upstream checklist).
confidence: high
rationale: Validate responses for over-broad object fields and sensitive data leakage.
manual_only: false
wstg_ids: [WSTG-APIT-03]
triggers:
  methods: ["GET", "POST"]
  path_contains: ["/api"]
tasks:
  - Compare full API responses across roles and identify fields that should be hidden.
  - Check whether internal identifiers, tokens, or privileged metadata are exposed.
  - Document field-level overexposure evidence with role/context.
---

Category: API Testing (WSTG-APIT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/03-Testing_for_Excessive_Data_Exposure
