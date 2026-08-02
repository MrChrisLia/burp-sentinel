---
id: WSTG-INFO-05
name: Review Web Page Content for Information Leakage
description: Auto-generated from OWASP WSTG (WSTG-INFO-05).
confidence: medium
rationale: Evidence-driven mapping for Review Web Page Content for Information Leakage.
manual_only: false
wstg_ids: [WSTG-INFO-05]
triggers:
  query_params: ["redirect", "redirect_uri", "next", "url", "return", "return_to"]
  status_codes: ["301", "302", "303", "307", "308"]
  js_finding_types: ["secret", "obfuscation"]
tasks:
  - Validate objective: Review web page comments, metadata, and redirect bodies to find any information leakage.
  - Validate objective: Gather JavaScript files and review the JS code to better understand the application and to find any information leakage.
  - Validate objective: Identify if source map files or other frontend debug files exist.
---

Category: Information Gathering (WSTG-INFO)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage
