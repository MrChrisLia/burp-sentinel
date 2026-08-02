---
id: WSTG-CLNT-10
name: Testing WebSockets
description: Auto-generated from OWASP WSTG (WSTG-CLNT-10).
confidence: medium
rationale: Evidence-driven mapping for Testing WebSockets.
manual_only: false
wstg_ids: [WSTG-CLNT-10]
triggers:
  path_contains: [".js", "/app", "/static", "/assets", "/ws", "/socket"]
  route_types: ["websocket"]
tasks:
  - Validate objective: Identify the usage of WebSockets.
  - Validate objective: Assess its implementation by using the same tests on normal HTTP channels.
---

Category: Client-side Testing (WSTG-CLNT)
Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
