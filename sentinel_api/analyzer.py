"""Heuristic request analyzer.

Evidence-driven and deterministic: signals come from the parsed request/response,
not from the LLM. The provider only writes the natural-language summary.
Mirrors the /analyze-request contract in the project plan (section 13.1).
"""
from __future__ import annotations

import os

import yaml

from sentinel_api import parser
from sentinel_api import endpoint_classifier
from sentinel_api import wstg_skills
from sentinel_api.providers import get_provider

_PROMPTS_DIR = os.path.join(os.path.dirname(__file__), "prompts")
_PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "playbooks")

# Path/param tokens that hint at security-sensitive object identifiers.
_ID_PARAM_HINTS = (
    "id", "user_id", "account_id", "org_id", "organization_id",
    "tenant_id", "project_id", "invoice_id", "order_id",
)


def _load_prompt(name: str) -> str:
    with open(os.path.join(_PROMPTS_DIR, name), encoding="utf-8") as f:
        return f.read()


def _load_playbooks() -> list[dict]:
    books = []
    if not os.path.isdir(_PLAYBOOKS_DIR):
        return books
    for fn in sorted(os.listdir(_PLAYBOOKS_DIR)):
        if fn.endswith((".yaml", ".yml")):
            with open(os.path.join(_PLAYBOOKS_DIR, fn), encoding="utf-8") as f:
                books.append(yaml.safe_load(f))
    return books


def _detect_signals(req: dict) -> list[str]:
    signals = []
    norm = parser.normalize_path(req["path"])
    if "{id}" in norm:
        signals.append("numeric_id_in_path")
    for hint in _ID_PARAM_HINTS:
        if hint in req["query_params"]:
            signals.append("object_id_parameter")
            break
    return signals


def _match_playbooks(signals: list[str], req: dict, playbooks: list[dict]) -> list[dict]:
    matches = []
    for pb in playbooks:
        pb_signals = set(pb.get("signals", []))
        if pb_signals & set(signals):
            matches.append(pb)
    return matches


def analyze(scope_name: str, known_role: str, raw_request: str,
            raw_response: str = "", tester_notes: str = "") -> dict:
    req = parser.parse_request(raw_request)
    resp = parser.parse_response(raw_response) if raw_response else {}

    signals = _detect_signals(req)
    playbooks = _load_playbooks()
    matched = _match_playbooks(signals, req, playbooks)

    # Endpoint summary via the (mock/real) provider.
    prompt = _load_prompt("request_analyzer.txt").format(
        method=req["method"], path=req["path"] or "/")
    summary = get_provider().complete(prompt)

    sensitive_params = endpoint_classifier.sensitive_parameters(req)

    likely_risks = []
    suggested_tests = []
    for pb in matched:
        likely_risks.append({
            "category": pb.get("owasp_category", "Unknown"),
            "reason": f"Endpoint matches playbook '{pb.get('name')}'.",
            "confidence": "medium",
        })
        suggested_tests.append({
            "name": pb.get("name", "Manual check"),
            "reason": "Object identifier or sensitive parameter observed.",
            "manual_steps": [
                "Capture the same request as User A.",
                "Replay it as User B.",
                "Swap object IDs.",
                "Compare response data and authorization behavior.",
            ],
            "repeater_mutations": [t for t in pb.get("tests", [])],
            "evidence_to_collect": [e for e in pb.get("evidence", [])],
        })

    wstg_recommendations = wstg_skills.recommend_for_request(req, resp)
    for rec in wstg_recommendations[:6]:
        objectives = rec.get("objectives", []) or []
        suggested_tests.append({
            "name": f"{rec.get('id')} - {rec.get('name')}",
            "reason": rec.get("rationale", "Mapped from observed traffic."),
            "manual_steps": objectives[:3] if objectives else [
                "Review the endpoint behavior against the WSTG scenario.",
                "Replay request variants in Burp Repeater.",
                "Record evidence for pass/fail and confidence.",
            ],
            "repeater_mutations": [],
            "evidence_to_collect": [rec.get("reference", "")] if rec.get("reference") else [],
        })

    model_updates = []
    norm = parser.normalize_path(req["path"])
    for seg in norm.split("/"):
        if seg and seg not in ("{id}", "api", "v1", "v2"):
            model_updates.append({
                "type": "feature_hint",
                "name": seg,
                "evidence": f"Path segment in {req['method']} {norm}",
            })

    return {
        "endpoint_summary": summary,
        "feature": endpoint_classifier.guess_feature(req["path"]),
        "workflow": f"{req['method']} {norm}",
        "business_objects": sensitive_params,
        "sensitive_parameters": sensitive_params,
        "likely_roles": [known_role] if known_role else [],
        "likely_risks": likely_risks,
        "suggested_tests": suggested_tests,
        "wstg_skills": wstg_recommendations,
        "risk_score": endpoint_classifier.risk_score(req),
        "parsed_request": req,
        "parsed_response": resp,
        "model_updates": model_updates,
    }
