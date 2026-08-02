---
id: WSTG-CRYP-02
name: Testing for Padding Oracle
description: Auto-generated from OWASP WSTG (WSTG-CRYP-02).
confidence: medium
rationale: Evidence-driven mapping for Testing for Padding Oracle.
manual_only: true
wstg_ids: [WSTG-CRYP-02]
triggers:
tasks:
  - Validate objective: Identify encrypted messages that rely on padding.
  - Validate objective: Attempt to break the padding of the encrypted messages and analyze the returned error messages for further analysis.
---

Category: Testing for Weak Cryptography (WSTG-CRYP)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle
