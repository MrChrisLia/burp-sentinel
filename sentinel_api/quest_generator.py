"""Quest generation from observed app model signals.

Quests are traffic-driven: reasons and tasks reference concrete endpoints/routes
seen in proxy/analyzer data.
"""
from __future__ import annotations


def _fmt_endpoints(endpoints: list[dict], limit: int = 3) -> str:
    parts = []
    for e in endpoints[:limit]:
        m = e.get("method", "")
        p = e.get("normalized_path", "")
        if m and p:
            parts.append(f"{m} {p}")
    return ", ".join(parts)


def _filter_paths(endpoints: list[dict], keywords: tuple[str, ...]) -> list[dict]:
    out = []
    for e in endpoints:
        p = (e.get("normalized_path") or "").lower()
        if any(k in p for k in keywords):
            out.append(e)
    return out


def _is_low_value_endpoint(endpoint: dict) -> bool:
    p = (endpoint.get("normalized_path") or "").lower()
    if any(x in p for x in ("wp-content", "/assets/", "/static/", "/fonts/", "/images/", "/favicon")):
        return True
    if p.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ico")):
        return True
    if any(x in p for x in ("/events/", "/ins/", "/telemetry", "/analytics", "/jserrors/", "/envelope", "/collect", "nrjs-")):
        return True
    return False


def generate(scope_name: str, model: dict) -> list[dict]:
    endpoints: list[dict] = sorted(
        model.get("endpoints", []),
        key=lambda x: int(x.get("risk_score", 0)),
        reverse=True,
    )
    candidate_endpoints = [e for e in endpoints if not _is_low_value_endpoint(e)]
    if not candidate_endpoints:
        candidate_endpoints = endpoints
    discovered_routes = model.get("discovered_routes", [])
    objects = model.get("business_objects", [])
    redirects = model.get("redirect_events", [])
    js_findings = model.get("js_findings", [])
    wstg_recommendations = model.get("wstg_recommendations", [])

    endpoint_paths = [e.get("normalized_path", "") for e in candidate_endpoints]
    id_endpoints = [e for e in candidate_endpoints if "{id}" in (e.get("normalized_path") or "")]
    role_endpoints = _filter_paths(candidate_endpoints, ("role", "permission", "member", "invite", "admin"))
    auth_endpoints = _filter_paths(candidate_endpoints, ("auth", "session", "login", "logout", "mfa", "token"))
    file_endpoints = _filter_paths(candidate_endpoints, ("upload", "download", "export", "file"))
    billing_endpoints = _filter_paths(candidate_endpoints, ("billing", "payment", "invoice", "subscription"))
    graphql_endpoints = _filter_paths(candidate_endpoints, ("graphql",))

    has_ids = bool(id_endpoints)
    has_roles = bool(role_endpoints)
    has_auth = bool(auth_endpoints)
    has_upload = bool(file_endpoints)
    has_graphql = bool(graphql_endpoints) or any(r.get("route_type") == "graphql" for r in discovered_routes)
    has_unobserved = any(not r.get("observed_in_proxy", False) for r in discovered_routes)
    has_redirects = bool(redirects)
    js_secret_findings = [f for f in js_findings if f.get("finding_type") == "secret"]
    js_hidden_endpoint_findings = [f for f in js_findings if f.get("finding_type") == "endpoint"]
    js_obfuscation_findings = [f for f in js_findings if f.get("finding_type") == "obfuscation"]

    def finding_source(f: dict) -> str:
        host = (f.get("source_host") or "").strip()
        path = (f.get("source_path") or "").strip()
        if host and path:
            return f"{host}{path}"
        if host:
            return host
        if path:
            return path
        return "unknown-source"

    quests: list[dict] = []

    if has_ids:
        examples = _fmt_endpoints(id_endpoints)
        quests.append({
            "name": "Tenant Boundary Quest",
            "reason": f"Observed object-ID endpoints: {examples}",
            "tasks": [
                {"description": f"Replay cross-user reads on: {examples}", "status": "todo"},
                {"description": "Swap object IDs across users/tenants and compare responses.", "status": "todo"},
                {"description": "Try write actions with mismatched object ownership.", "status": "todo"},
                {"description": "Capture evidence (status, body differences, owner fields).", "status": "todo"},
            ],
        })

    if has_roles:
        examples = _fmt_endpoints(role_endpoints)
        quests.append({
            "name": "Role Escalation Quest",
            "reason": f"Role-sensitive endpoints observed: {examples}",
            "tasks": [
                {"description": f"Replay privileged actions on: {examples}", "status": "todo"},
                {"description": "Attempt same actions with lower-privileged sessions.", "status": "todo"},
                {"description": "Mutate role/permission fields and verify server-side effect.", "status": "todo"},
            ],
        })

    if has_auth:
        examples = _fmt_endpoints(auth_endpoints)
        quests.append({
            "name": "Auth/Session Quest",
            "reason": f"Authentication/session flows observed: {examples}",
            "tasks": [
                {"description": "Check session invalidation and logout token behavior.", "status": "todo"},
                {"description": "Probe MFA/state transitions for bypass assumptions.", "status": "todo"},
                {"description": "Compare response differences across valid/expired sessions.", "status": "todo"},
            ],
        })

    if has_upload:
        examples = _fmt_endpoints(file_endpoints)
        quests.append({
            "name": "Upload/Download Quest",
            "reason": f"File-related endpoints observed: {examples}",
            "tasks": [
                {"description": "Validate authorization on download/export URLs.", "status": "todo"},
                {"description": "Check file replacement/overwrite and metadata exposure.", "status": "todo"},
                {"description": "Verify storage access control and direct object access.", "status": "todo"},
            ],
        })

    if has_redirects:
        redirect_targets = sorted({r.get("target_host", "") for r in redirects if r.get("target_host")})
        target_text = ", ".join(redirect_targets[:4]) if redirect_targets else "observed redirect targets"
        quests.append({
            "name": "Redirect Validation Quest",
            "reason": f"Redirect chains observed toward: {target_text}",
            "tasks": [
                {"description": "Test redirect parameters for open-redirect behavior.", "status": "todo"},
                {"description": "Check allowlist/denylist enforcement for external redirect targets.", "status": "todo"},
                {"description": "Verify auth/session state across redirect boundaries.", "status": "todo"},
            ],
        })

    if js_secret_findings or js_hidden_endpoint_findings or js_obfuscation_findings:
        sample_secrets = ", ".join(
            f"{f.get('category')}: {f.get('indicator')} @ {finding_source(f)}"
            for f in js_secret_findings[:3]
        )
        sample_hidden = ", ".join(
            f"{f.get('indicator', '')} (from {finding_source(f)})"
            for f in js_hidden_endpoint_findings[:3]
        )
        reason_parts = []
        if js_secret_findings:
            reason_parts.append(f"Detected {len(js_secret_findings)} potential hardcoded secret findings")
        if js_hidden_endpoint_findings:
            reason_parts.append(f"Detected {len(js_hidden_endpoint_findings)} hidden endpoint findings")
        if js_obfuscation_findings:
            reason_parts.append(f"Detected {len(js_obfuscation_findings)} JS obfuscation signals")
        reason = ". ".join(reason_parts) + "."
        quests.append(
            {
                "name": "JavaScript Intelligence Quest",
                "reason": reason,
                "tasks": [
                    {"description": "Review/deobfuscate high-signal JavaScript bundles and verify decoded artifacts.", "status": "todo"},
                    {"description": f"Validate potential secrets are real and active (sample): {sample_secrets or 'none'}", "status": "todo"},
                    {"description": f"Probe hidden JS-discovered endpoints (sample): {sample_hidden or 'none'}", "status": "todo"},
                    {"description": "Trace each JS finding back to its source endpoint and prioritize by exploitability.", "status": "todo"},
                    {"description": "Rotate/revoke any confirmed exposed credentials and document impacted integrations.", "status": "todo"},
                ],
            }
        )

    if wstg_recommendations:
        tasks = []
        for rec in wstg_recommendations:
            rid = rec.get("id", "")
            name = rec.get("name", "")
            rationale = rec.get("rationale", "")
            tasks.append({
                "description": f"Execute {rid} ({name}) - {rationale}",
                "status": "todo",
            })
        quests.append({
            "name": "WSTG Skills Quest",
            "reason": "Mapped directly from OWASP WSTG checklist IDs based on observed traffic evidence.",
            "tasks": tasks,
        })

    api_discovery_tasks = [
        {"description": "Review observed hosts and confirm first-party API boundaries.", "status": "todo"},
        {"description": f"Prioritize high-risk endpoints: {_fmt_endpoints(candidate_endpoints)}", "status": "todo"},
        {"description": "Review JavaScript-discovered routes against observed proxy traffic.", "status": "todo"},
        {"description": "Confirm scope before testing additional domains.", "status": "todo"},
    ]
    if has_graphql:
        api_discovery_tasks.append({"description": "Test GraphQL routes for authz and field-level access controls.", "status": "todo"})
    if has_unobserved:
        unobs = [r for r in discovered_routes if not r.get("observed_in_proxy", False)]
        sample = ", ".join((r.get("route") or "") for r in unobs[:3])
        api_discovery_tasks.append({"description": f"Investigate discovered-not-observed routes: {sample}", "status": "todo"})
    if objects:
        api_discovery_tasks.append({"description": f"Cross-check object coverage for: {', '.join(objects[:8])}", "status": "todo"})
    if billing_endpoints:
        api_discovery_tasks.append({"description": f"Validate billing/payment flows: {_fmt_endpoints(billing_endpoints)}", "status": "todo"})
    if js_secret_findings:
        sample = ", ".join(
            f"{f.get('category')} ({f.get('indicator')}) from {finding_source(f)}"
            for f in js_secret_findings[:2]
        )
        api_discovery_tasks.append({"description": f"Cross-check JS secret findings against backend auth flows: {sample}", "status": "todo"})
    if js_hidden_endpoint_findings:
        sample = ", ".join(
            f"{f.get('indicator', '')} from {finding_source(f)}"
            for f in js_hidden_endpoint_findings[:2]
        )
        api_discovery_tasks.append({"description": f"Confirm hidden JS endpoints are represented in traffic coverage: {sample}", "status": "todo"})

    quests.append({
        "name": "API Discovery Quest",
        "reason": "Built from observed proxy traffic, discovered routes, JS intelligence findings, and risk-ranked endpoints.",
        "tasks": api_discovery_tasks,
    })
    return quests
