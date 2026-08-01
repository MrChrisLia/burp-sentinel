"""Parse raw HTTP request/response text into structured data.

Passive-first and evidence-driven: we only extract what is present.
Sensitive values are redacted by default (safety rule).
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlparse

REDACTED = "[REDACTED]"
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
SENSITIVE_BODY_KEYS = {"password", "token", "api_key", "apikey", "secret", "access_token"}


def split_headers_body(raw: str) -> tuple[str, str]:
    raw = raw.replace("\r\n", "\n")
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    return head, body


def redact_raw(raw: str) -> str:
    """Redact sensitive header values in a raw HTTP message, keep the body."""
    if not raw:
        return ""
    head, body = split_headers_body(raw)
    out_lines = []
    for line in head.split("\n"):
        if ":" in line:
            name = line.split(":", 1)[0].strip().lower()
            if name in SENSITIVE_HEADERS:
                line = f"{line.split(':', 1)[0]}: {REDACTED}"
        out_lines.append(line)
    return "\n".join(out_lines) + ("\n\n" + body if body else "")


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def _body_shape(body: str, content_type: str) -> dict:
    """Describe body without leaking secrets: top-level JSON keys, or length."""
    if "json" in content_type.lower() and body.strip():
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                keys = sorted(data.keys())
                return {"type": "json", "keys": keys, "length": len(body)}
            if isinstance(data, list):
                return {"type": "json_array", "length": len(data)}
        except json.JSONDecodeError:
            pass
    return {"type": content_type or "unknown", "length": len(body)}


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(body: str) -> str:
    """Pull the <title> text out of an HTML response body (max 200 chars)."""
    if not body:
        return ""
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    title = re.sub(r"<[^>]+>", "", m.group(1))
    title = re.sub(r"\s+", " ", title).strip()
    return title[:200]


def parse_request(raw: str) -> dict:
    head, body = split_headers_body(raw)
    lines = head.split("\n")
    request_line = lines[0].strip() if lines else ""
    parts = request_line.split()
    method = parts[0] if len(parts) >= 1 else ""
    target = parts[1] if len(parts) >= 2 else ""

    headers = _parse_headers(lines[1:])
    host = headers.get("host", "")

    # Build a parseable URL from Host + target.
    scheme = "https"
    parsed = urlparse(target if target.startswith("http") else f"{scheme}://{host}{target}")
    query_params = sorted(parse_qs(parsed.query).keys())
    content_type = headers.get("content-type", "")

    return {
        "method": method,
        "scheme": parsed.scheme or scheme,
        "host": parsed.hostname or host,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query_params": query_params,
        "content_type": content_type,
        "body_shape": _body_shape(body, content_type),
        "auth_header_present": "authorization" in headers,
        "cookies_present": "cookie" in headers,
        "origin": headers.get("origin"),
        "referer": headers.get("referer"),
        "sec_fetch_site": headers.get("sec-fetch-site"),
        "sec_fetch_mode": headers.get("sec-fetch-mode"),
        "user_agent": headers.get("user-agent"),
        "websocket_upgrade": headers.get("upgrade", "").lower() == "websocket",
        "headers": _redact_headers(headers),
    }


def parse_response(raw: str, include_body: bool = False) -> dict:
    if not raw:
        return {}
    head, body = split_headers_body(raw)
    lines = head.split("\n")
    status_line = lines[0].strip() if lines else ""
    m = re.search(r"\b(\d{3})\b", status_line)
    status_code = int(m.group(1)) if m else None

    headers = _parse_headers(lines[1:])
    content_type = headers.get("content-type", "")
    cors = {k: v for k, v in headers.items() if k.startswith("access-control-")}
    location = headers.get("location", "")
    is_redirect = status_code in {301, 302, 303, 307, 308} and bool(location)
    redirect_target_host = ""
    if location:
        try:
            redirect_target_host = (urlparse(location).hostname or "").lower()
        except ValueError:
            redirect_target_host = ""

    payload = {
        "status_code": status_code,
        "content_type": content_type,
        "body_shape": _body_shape(body, content_type),
        "cors_headers": cors,
        "set_cookie_present": "set-cookie" in headers,
        "response_length": len(body),
        "is_redirect": is_redirect,
        "redirect_location": location,
        "redirect_target_host": redirect_target_host,
        "headers": _redact_headers(headers),
        "title": extract_title(body) if "html" in content_type.lower() else "",
    }
    if include_body:
        payload["body"] = body
    return payload


# Path segments that look like object identifiers (IDOR signal).
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def normalize_path(path: str) -> str:
    """Replace id-looking segments with {id} so endpoints cluster together."""
    out = []
    for seg in path.split("/"):
        if _NUMERIC.match(seg) or _UUID.match(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)
