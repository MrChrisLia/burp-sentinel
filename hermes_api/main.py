"""Hermes backend.

Implements the backend-first roadmap from the project plan:
- /health
- /analyze-request
- /proxy/import
- /app-summary/{scope_name}
- /generate-quests
- /quests
- /quests/{id}/complete-task
- /evidence
"""
from __future__ import annotations

import json
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from hermes_api import analyzer
from hermes_api import endpoint_classifier
from hermes_api import parser
from hermes_api import proxy_mapper
from hermes_api import quest_generator
from hermes_api import wstg_skills
from hermes_api import markdown_skills
from hermes_api.config import settings
from hermes_api.evidence import normalize_confidence
from hermes_api.providers import get_provider
from hermes_api.storage import store

app = FastAPI(title="Hermes Web App Navigator", version="0.2.0")


class AnalyzeRequest(BaseModel):
    scope_name: str
    known_role: str = ""
    request: str
    response: str = ""
    tester_notes: str = ""
    source_tool: str = "manual"


class GenerateQuestsRequest(BaseModel):
    scope_name: str
    quest_type: str = "auto"


class ScopeCreateRequest(BaseModel):
    scope_name: str


class ChatRequest(BaseModel):
    scope_name: str
    message: str


class ProxyImportItem(BaseModel):
    request: str
    response: str = ""
    tool: str = "proxy"
    timestamp: str = ""


class ProxyImportRequest(BaseModel):
    scope_name: str
    items: list[ProxyImportItem] = Field(default_factory=list)


class EvidenceRequest(BaseModel):
    scope_name: str
    title: str
    category: str
    endpoint: str
    request: str
    response: str = ""
    notes: str = ""
    confidence: str = "medium"


class CompleteQuestTaskRequest(BaseModel):
    scope_name: str
    task_id: int


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "provider": settings.provider,
        "db_path": settings.db_path,
        "base_url": settings.base_url,
        "model": settings.model,
        "api_key_present": bool(settings.api_key),
    }


@app.get("/scopes")
def list_scopes() -> dict:
    return {"scopes": store.list_scopes()}


@app.get("/skills")
def list_skills(refresh: bool = False) -> dict:
    skills = markdown_skills.reload_markdown_skills() if refresh else markdown_skills.load_markdown_skills()
    return {
        "skills_dir": markdown_skills.skills_dir(),
        "count": len(skills),
        "skills": [
            {
                "id": s.get("id", ""),
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "confidence": s.get("confidence", "medium"),
                "wstg_ids": s.get("wstg_ids", []),
                "source_file": s.get("source_file", ""),
            }
            for s in skills
        ],
    }


@app.post("/scopes")
def create_scope(body: ScopeCreateRequest) -> dict:
    name = body.scope_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="scope_name is required")
    scope_id = store.ensure_scope(name)
    return {"created": True, "scope_id": scope_id, "scope_name": name}


@app.delete("/scopes/{scope_name}")
def delete_scope(scope_name: str) -> dict:
    name = scope_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="scope_name is required")
    deleted = store.delete_scope(name)
    if not deleted:
        raise HTTPException(status_code=404, detail="scope not found")
    return {"deleted": True, "scope_name": name}


class HostsScopeRequest(BaseModel):
    hosts: list[str]
    in_scope: bool = True
    exclusive: bool = False


@app.get("/scopes/{scope_name}/hosts")
def scope_hosts_get(scope_name: str) -> dict:
    """Saved per-host filter for a scope (host, classification, in_scope)."""
    name = scope_name.strip()
    return {"scope_name": name, "hosts": store.list_hosts(name)}


@app.post("/scopes/{scope_name}/hosts")
def scope_hosts(scope_name: str, body: HostsScopeRequest) -> dict:
    """Mark hosts in/out of scope. Out-of-scope hosts are excluded from
    summaries, chat context, and quest generation (rows are kept, reversible).
    With exclusive=true the given list is treated as the full in-scope set:
    every other host of the scope is flipped to the opposite flag."""
    name = scope_name.strip()
    updated = store.set_hosts_in_scope(
        name,
        [h.strip().lower() for h in body.hosts if h.strip()],
        body.in_scope,
        exclusive=body.exclusive,
    )
    return {"updated": updated, "scope_name": name, "in_scope": body.in_scope, "exclusive": body.exclusive}


@app.post("/analyze-request")
def analyze_request(body: AnalyzeRequest) -> dict:
    result = analyzer.analyze(
        scope_name=body.scope_name,
        known_role=body.known_role,
        raw_request=body.request,
        raw_response=body.response,
        tester_notes=body.tester_notes,
    )

    req = result["parsed_request"]
    resp = result.get("parsed_response", {})
    store.record_role(body.scope_name, body.known_role)
    store.record_domain(
        body.scope_name,
        req.get("host", ""),
        endpoint_classifier.classify_host(req, resp),
        confidence="medium",
    )
    store.record_relationship(body.scope_name, endpoint_classifier.relationship_from_headers(req, resp))
    store.record_endpoint(
        body.scope_name,
        method=req.get("method", ""),
        host=req.get("host", ""),
        path=req.get("path", ""),
        normalized_path=parser.normalize_path(req.get("path", "")),
        query_params=req.get("query_params", []),
        content_type=req.get("content_type", ""),
        auth_observed=bool(req.get("auth_header_present") or req.get("cookies_present")),
        source_tool=body.source_tool,
        feature=result.get("feature", "unknown"),
        workflow=result.get("workflow", ""),
        risk_score=int(result.get("risk_score", 0)),
    )
    store.record_business_objects(body.scope_name, result.get("business_objects", []))
    if resp.get("is_redirect"):
        store.record_redirect(
            body.scope_name,
            source_host=req.get("host", ""),
            source_path=req.get("path", ""),
            status_code=int(resp.get("status_code") or 0),
            location=resp.get("redirect_location", ""),
        )

    # Public contract should not expose internal parsed payloads.
    result.pop("parsed_request", None)
    result.pop("parsed_response", None)
    return result


@app.post("/proxy/import")
def proxy_import(body: ProxyImportRequest) -> dict:
    imported = 0
    new_endpoints = 0
    js_routes_discovered = 0
    js_findings_discovered = 0

    for item in body.items:
        imported += 1
        req = parser.parse_request(item.request)
        resp = parser.parse_response(item.response) if item.response else {}

        classification = endpoint_classifier.classify_host(req, resp)
        store.record_domain(body.scope_name, req.get("host", ""), classification, confidence="medium")
        store.record_relationship(body.scope_name, endpoint_classifier.relationship_from_headers(req, resp))

        if resp.get("title"):
            store.record_page_title(
                body.scope_name,
                req.get("host", ""),
                req.get("path", ""),
                resp["title"],
            )

        store.record_traffic(
            body.scope_name,
            host=req.get("host", ""),
            method=req.get("method", ""),
            path=req.get("path", "/"),
            query_string=",".join(req.get("query_params", [])),
            status_code=resp.get("status_code"),
            content_type=resp.get("content_type", ""),
            request_raw=item.request,
            response_raw=item.response or "",
        )

        normalized_path = parser.normalize_path(req.get("path", ""))
        is_new = store.record_endpoint(
            body.scope_name,
            method=req.get("method", ""),
            host=req.get("host", ""),
            path=req.get("path", ""),
            normalized_path=normalized_path,
            query_params=req.get("query_params", []),
            content_type=req.get("content_type", ""),
            auth_observed=bool(req.get("auth_header_present") or req.get("cookies_present")),
            source_tool=item.tool,
            feature=endpoint_classifier.guess_feature(req.get("path", "")),
            workflow=f"{req.get('method', '')} {normalized_path}",
            risk_score=endpoint_classifier.risk_score(req),
        )
        if is_new:
            new_endpoints += 1

        # Enrich app model from proxy-imported traffic so summaries are useful
        # even before manual /analyze-request calls.
        store.record_business_objects(
            body.scope_name,
            endpoint_classifier.infer_business_objects(req, resp),
        )
        for inferred_role in endpoint_classifier.infer_roles(req, resp):
            store.record_role(body.scope_name, inferred_role)
        if resp.get("is_redirect"):
            store.record_redirect(
                body.scope_name,
                source_host=req.get("host", ""),
                source_path=req.get("path", ""),
                status_code=int(resp.get("status_code") or 0),
                location=resp.get("redirect_location", ""),
            )

        store.mark_route_observed(body.scope_name, normalized_path)

        if item.response:
            js_analysis = proxy_mapper.analyze_javascript(item.response)
            routes = js_analysis.get("routes", [])
            findings = js_analysis.get("findings", [])
            js_routes_discovered += store.record_discovered_routes(body.scope_name, routes)
            js_findings_discovered += store.record_js_findings(
                body.scope_name,
                source_host=req.get("host", ""),
                source_path=req.get("path", ""),
                findings=findings,
            )

    stats = store.proxy_import_stats(body.scope_name)
    summary = store.summary(body.scope_name)

    high_value_findings = []
    for host in summary.get("likely_api_hosts", [])[:3]:
        high_value_findings.append(f"{host} contains authenticated or security-relevant endpoints")
    if any("admin/internal" in s for s in summary.get("untested_areas", [])):
        high_value_findings.append("JavaScript references admin/internal routes not observed in proxy traffic")
    if summary.get("javascript_secret_findings"):
        high_value_findings.append("Potential hardcoded keys/secrets discovered in JavaScript bundles")
    if summary.get("javascript_obfuscation_signals"):
        high_value_findings.append("JavaScript obfuscation/minification signals detected; manual review recommended")
    snapshot = store.app_snapshot(body.scope_name)
    wstg_recs = wstg_skills.recommend_for_snapshot(snapshot, limit=3)
    if wstg_recs:
        high_value_findings.append(
            "WSTG skills selected: " + ", ".join(r.get("id", "") for r in wstg_recs if r.get("id"))
        )

    return {
        "imported": imported,
        "domains_discovered": stats["domains_discovered"],
        "api_hosts_discovered": stats["api_hosts_discovered"],
        "new_endpoints": new_endpoints,
        "javascript_routes_discovered": js_routes_discovered,
        "javascript_findings_discovered": js_findings_discovered,
        "high_value_findings": high_value_findings,
    }


@app.get("/app-summary/{scope_name}")
def app_summary(scope_name: str) -> dict:
    data = store.summary(scope_name)
    snapshot = store.app_snapshot(scope_name)
    wstg_recs = wstg_skills.recommend_for_snapshot(snapshot, limit=1000)
    return {
        "scope_name": scope_name,
        **data,
        "wstg_recommended_skills": [
            f"{r.get('id')} - {r.get('name')}"
            for r in wstg_recs
        ],
        "wstg_recommended_skill_details": wstg_recs,
    }


@app.post("/generate-quests")
def generate_quests(body: GenerateQuestsRequest) -> dict:
    snapshot = store.app_snapshot(body.scope_name)
    snapshot["wstg_recommendations"] = wstg_skills.recommend_for_snapshot(snapshot, limit=1000)
    quests = quest_generator.generate(body.scope_name, snapshot)
    quest_ids = [store.upsert_quest(body.scope_name, q) for q in quests]
    return {"quests": quests, "quest_ids": quest_ids}


@app.get("/quests/{scope_name}")
def list_quests(scope_name: str) -> dict:
    return {"scope_name": scope_name, "quests": store.list_quests(scope_name)}


@app.post("/quests/{quest_id}/complete-task")
def complete_quest_task(quest_id: int, body: CompleteQuestTaskRequest) -> dict:
    ok = store.complete_task(body.scope_name, quest_id=quest_id, task_id=body.task_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Quest/task not found")
    return {"updated": True, "quest_id": quest_id, "task_id": body.task_id}


@app.post("/evidence")
def save_evidence(body: EvidenceRequest) -> dict:
    evidence_id = store.save_evidence(
        scope_name=body.scope_name,
        title=body.title,
        category=body.category,
        endpoint=body.endpoint,
        request=body.request,
        response=body.response,
        notes=body.notes,
        confidence=normalize_confidence(body.confidence),
    )
    return {"saved": True, "evidence_id": evidence_id}


_HOST_RE = re.compile(r"(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)

_PATH_HINT_RE = re.compile(r"[\w./-]+\.(?:js|json|php|html?|xml|txt|css|env|conf|config|ya?ml|ini|log|bak|sql|py|rb|go)\b", re.I)
_SLASH_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]{2,}")


def _extract_path_hint(message: str) -> str | None:
    """Pull a file/path the user is asking about (e.g. 'config.js', '/api/x')."""
    m = _PATH_HINT_RE.search(message)
    if m:
        return m.group(0).strip("'\",.;:!?")
    m = _SLASH_PATH_RE.search(message)
    if m:
        return m.group(0).strip("'\",.;:!?")
    return None


_TRAFFIC_ITEM_CAP = 6_000
_TRAFFIC_TOTAL_CAP = 40_000

_SECRET_PATTERNS = [
    (r"\bsk-[A-Za-z0-9_-]{16,}\b", "OpenAI-style API key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key"),
    (r"\bAIza[0-9A-Za-z_-]{30,}\b", "Google API key"),
    (r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "Slack token"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key block"),
    (r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "credential assignment"),
]


def _scan_secrets(blocks: list[str]) -> list[str]:
    """Deterministic regex scan over the traffic blocks for common secret shapes."""
    found: list[str] = []
    seen: set[str] = set()
    for block in blocks:
        for pattern, label in _SECRET_PATTERNS:
            for m in re.finditer(pattern, block):
                snippet = m.group(0)
                if len(snippet) > 90:
                    snippet = snippet[:45] + "..." + snippet[-20:]
                key = f"{label}:{snippet}"
                if key in seen:
                    continue
                seen.add(key)
                found.append(f"{label}: {snippet}")
    return found[:15]


def _build_traffic_blocks(scope_name: str, focus_host: str | None, message: str) -> tuple[str, list[str]]:
    """Fetch relevant request/response pairs and render them for the prompt."""
    path_hint = _extract_path_hint(message)
    items = store.search_traffic(
        scope_name,
        host=focus_host,
        path_contains=path_hint,
        limit=8 if path_hint else 6,
    )
    if not items:
        return "", []
    blocks: list[str] = []
    total = 0
    for it in items:
        head = (
            f"--- {it['method']} {it['host']}{it['path']} "
            f"(HTTP {it['status_code'] or '?'}, {it['content_type'] or 'unknown'}, "
            f"seen {it['seen_count']}x, last {it['last_seen']}) ---"
        )
        req = it["request"] or "(no request captured)"
        if len(req) > 1_500:
            req = req[:1_500] + "\n...[request truncated]..."
        resp = it["response"]
        if not resp:
            resp = "(no response body captured)" if it["binary_response"] else "(no response captured)"
        else:
            if len(resp) > _TRAFFIC_ITEM_CAP:
                resp = resp[:_TRAFFIC_ITEM_CAP] + "\n...[response truncated]..."
            resp = "--- RESPONSE ---\n" + resp
        block = f"{head}\n--- REQUEST ---\n{req}\n{resp}"
        if total + len(block) > _TRAFFIC_TOTAL_CAP:
            break
        blocks.append(block)
        total += len(block)
    text = "\n\n".join(blocks)
    return text, blocks


def _resolve_focus_host(scope_name: str, message: str) -> str | None:
    """Host the user is asking about: one mentioned in the message, or the
    most recently browsed in-scope host."""
    for m in _HOST_RE.finditer(message):
        host = m.group(0).lower()
        if host.startswith("http://"):
            host = host[7:]
        elif host.startswith("https://"):
            host = host[8:]
        if host.startswith("www."):
            host = host[4:]
        if host and store.host_context(scope_name, host):
            return host
    return store.most_recent_host(scope_name)


@app.post("/chat")
def chat(body: ChatRequest) -> dict:
    scope_name = body.scope_name.strip()
    message = body.message.strip()
    if not scope_name:
        raise HTTPException(status_code=400, detail="scope_name is required")
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    context = store.summary(scope_name)
    context_json = json.dumps(context, ensure_ascii=True)

    focus_host = _resolve_focus_host(scope_name, message)
    focus_section = ""
    if focus_host:
        host_data = store.host_context(scope_name, focus_host)
        if host_data:
            focus_section = (
                "\n\nFOCUS HOST — the user is asking about this host: "
                + json.dumps(host_data, ensure_ascii=True)
                + "\nIf the question concerns a page, endpoints, or the site "
                "they were just browsing, answer ONLY from this FOCUS HOST data. "
                "Do not use other hosts' endpoints, pages, or features in the answer."
            )

    traffic_text, traffic_blocks = _build_traffic_blocks(scope_name, focus_host, message)
    traffic_section = ""
    if traffic_text:
        traffic_section = (
            "\n\nCAPTURED REQUEST/RESPONSE BLOCKS (from the user's proxied traffic, "
            "sensitive headers redacted):\n" + traffic_text
        )
        secret_hits = _scan_secrets(traffic_blocks)
        if secret_hits:
            traffic_section += (
                "\n\nAUTOMATIC SECRET SCAN — deterministic regex matches found in the blocks above:\n"
                + "\n".join(f"- {h}" for h in secret_hits)
                + "\nVerify each hit by reading the blocks; report exact locations (file/endpoint)."
            )

    system_prompt = (
        "You are Hermes, a web application security copilot inside Burp Suite. "
        "Answer concisely, be technically correct, and ground answers in the provided scope context. "
        "The user browses sites through the Burp proxy; recent_pages lists the most recently viewed "
        "pages (newest first) and every endpoint is labeled with its host. "
        "IMPORTANT: when the user asks about a specific site, page, or host (or about what they "
        "just browsed), answer ONLY from that host's data — never mix data from different hosts, "
        "and never substitute another host's endpoints or pages. "
        "When CAPTURED REQUEST/RESPONSE BLOCKS are present and the user asks about a file or endpoint "
        "(e.g. 'config.js', 'that endpoint'), read the blocks and answer from their actual content: "
        "quote hardcoded credentials, secrets, dangerous sinks, debug flags, or suspicious config "
        "values with the exact file/endpoint they came from. If the blocks do not contain what the "
        "user asked about, say so explicitly instead of guessing. "
        "If context is missing, say what traffic/scope data is needed."
    )
    user_prompt = (
        f"Scope: {scope_name}\n"
        f"Scope summary JSON:\n{context_json}\n"
        f"{focus_section}"
        f"{traffic_section}\n\n"
        f"Question:\n{message}"
    )
    answer = get_provider().chat(system_prompt, user_prompt)
    return {"scope_name": scope_name, "answer": answer}
