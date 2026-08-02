"""SQLite-backed app model store.

The project plan's MVP prefers SQLite persistence so model state survives process
restarts and supports quest/evidence tracking.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock
from typing import Iterator
from urllib.parse import urlparse

from sentinel_api import parser


class Store:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._lock = Lock()
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    classification TEXT NOT NULL DEFAULT 'unknown',
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    in_scope INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    UNIQUE(app_id, host),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS domain_relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    source_host TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    UNIQUE(app_id, source_host, target_host, relationship_type),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    normalized_path TEXT NOT NULL,
                    query_params TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    auth_observed INTEGER NOT NULL DEFAULT 0,
                    source_tool TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    feature TEXT NOT NULL DEFAULT 'unknown',
                    workflow TEXT NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    tested_status TEXT NOT NULL DEFAULT 'untested',
                    notes TEXT NOT NULL DEFAULT '',
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(app_id, method, host, normalized_path),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS business_objects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    example_parameters TEXT NOT NULL DEFAULT '',
                    example_values TEXT NOT NULL DEFAULT '',
                    sensitivity TEXT NOT NULL DEFAULT 'medium',
                    UNIQUE(app_id, name),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    role_name TEXT NOT NULL,
                    UNIQUE(app_id, role_name),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS discovered_routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    source_file TEXT NOT NULL DEFAULT 'proxy_js',
                    route TEXT NOT NULL,
                    route_type TEXT NOT NULL,
                    host TEXT,
                    normalized_path TEXT NOT NULL,
                    observed_in_proxy INTEGER NOT NULL DEFAULT 0,
                    tested_status TEXT NOT NULL DEFAULT 'untested',
                    notes TEXT NOT NULL DEFAULT '',
                    UNIQUE(app_id, route),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS quests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'todo',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(app_id, name),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS quest_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quest_id INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'todo',
                    related_endpoint TEXT NOT NULL DEFAULT '',
                    evidence_id TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(quest_id) REFERENCES quests(id)
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    request TEXT NOT NULL,
                    response TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS redirect_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    source_host TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    location TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(app_id, source_host, source_path, status_code, location),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS page_titles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    title TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(app_id, host, path),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    host TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT NOT NULL DEFAULT '',
                    status_code INTEGER,
                    content_type TEXT NOT NULL DEFAULT '',
                    request TEXT NOT NULL DEFAULT '',
                    response TEXT NOT NULL DEFAULT '',
                    binary_response INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(app_id, method, host, path),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );

                CREATE TABLE IF NOT EXISTS js_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_id INTEGER NOT NULL,
                    source_host TEXT NOT NULL DEFAULT '',
                    source_path TEXT NOT NULL DEFAULT '',
                    finding_type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    confidence TEXT NOT NULL DEFAULT 'medium',
                    evidence TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(app_id, source_host, source_path, finding_type, category, indicator),
                    FOREIGN KEY(app_id) REFERENCES apps(id)
                );
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _app_id(self, conn: sqlite3.Connection, scope_name: str) -> int:
        row = conn.execute("SELECT id FROM apps WHERE name = ?", (scope_name,)).fetchone()
        now = self._now()
        if row:
            conn.execute("UPDATE apps SET updated_at = ? WHERE id = ?", (now, row["id"]))
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO apps(name, created_at, updated_at) VALUES (?, ?, ?)",
            (scope_name, now, now),
        )
        return int(cur.lastrowid)

    def ensure_scope(self, scope_name: str) -> int:
        with self._lock, self._conn() as conn:
            return self._app_id(conn, scope_name)

    def delete_scope(self, scope_name: str) -> bool:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT id FROM apps WHERE name = ?", (scope_name,)).fetchone()
            if not row:
                return False
            app_id = int(row["id"])

            conn.execute("DELETE FROM quest_tasks WHERE quest_id IN (SELECT id FROM quests WHERE app_id = ?)", (app_id,))
            conn.execute("DELETE FROM quests WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM evidence WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM redirect_events WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM js_findings WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM discovered_routes WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM roles WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM business_objects WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM endpoints WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM domain_relationships WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM page_titles WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM traffic WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM domains WHERE app_id = ?", (app_id,))
            conn.execute("DELETE FROM apps WHERE id = ?", (app_id,))
            return True

    def list_hosts(self, scope_name: str) -> list[dict]:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            rows = conn.execute(
                "SELECT host, classification, in_scope FROM domains WHERE app_id = ? ORDER BY host",
                (app_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def set_hosts_in_scope(self, scope_name: str, hosts: list[str], in_scope: bool, exclusive: bool = False) -> int:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            if not hosts:
                return 0
            placeholders = ",".join("?" for _ in hosts)
            cur = conn.execute(
                f"UPDATE domains SET in_scope = ? WHERE app_id = ? AND host IN ({placeholders})",
                [1 if in_scope else 0, app_id, *hosts],
            )
            if exclusive:
                # Mirror the extension's domain filter: everything NOT in the
                # list gets the opposite flag.
                conn.execute(
                    f"UPDATE domains SET in_scope = ? WHERE app_id = ? AND host NOT IN ({placeholders})",
                    [0 if in_scope else 1, app_id, *hosts],
                )
            return cur.rowcount

    def record_page_title(self, scope_name: str, host: str, path: str, title: str) -> None:
        if not host or not title:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            conn.execute(
                """
                INSERT INTO page_titles (app_id, host, path, title, first_seen, last_seen, seen_count)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(app_id, host, path) DO UPDATE SET
                    title = excluded.title,
                    last_seen = excluded.last_seen,
                    seen_count = seen_count + 1
                """,
                (app_id, host, path, title, now, now),
            )

    _TRAFFIC_RESPONSE_CAP = 200_000
    _TRAFFIC_REQUEST_CAP = 50_000
    _BINARY_CONTENT_TYPES = (
        "image/", "font/", "video/", "audio/", "application/octet-stream",
        "application/pdf", "application/zip", "application/gzip", "application/x-",
    )

    def record_traffic(
        self,
        scope_name: str,
        host: str,
        method: str,
        path: str,
        query_string: str,
        status_code: int | None,
        content_type: str,
        request_raw: str,
        response_raw: str,
    ) -> None:
        """Store one redacted request/response pair, deduped per endpoint path."""
        if not host:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            ctype = (content_type or "").lower()
            binary = int(any(ctype.startswith(p) for p in self._BINARY_CONTENT_TYPES))
            request = parser.redact_raw(request_raw)[: self._TRAFFIC_REQUEST_CAP]
            if binary:
                response = ""
            else:
                response = parser.redact_raw(response_raw)[: self._TRAFFIC_RESPONSE_CAP]
            conn.execute(
                """
                INSERT INTO traffic (
                    app_id, host, method, path, query_string, status_code, content_type,
                    request, response, binary_response, first_seen, last_seen, seen_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(app_id, method, host, path) DO UPDATE SET
                    query_string = excluded.query_string,
                    status_code = excluded.status_code,
                    content_type = excluded.content_type,
                    request = excluded.request,
                    response = excluded.response,
                    binary_response = excluded.binary_response,
                    last_seen = excluded.last_seen,
                    seen_count = seen_count + 1
                """,
                (
                    app_id, host, method, path, query_string[:500], status_code, ctype,
                    request, response, binary, now, now,
                ),
            )

    def search_traffic(
        self,
        scope_name: str,
        host: str | None = None,
        path_contains: str | None = None,
        limit: int = 6,
    ) -> list[dict]:
        """Recent in-scope traffic, optionally filtered by host and path text."""
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            sql = (
                "SELECT host, method, path, query_string, status_code, content_type, "
                "request, response, binary_response, last_seen, seen_count "
                "FROM traffic WHERE app_id = ? "
                "AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)"
            )
            params: list = [app_id, app_id]
            if host:
                sql += " AND host = ?"
                params.append(host)
            if path_contains:
                sql += " AND path LIKE ?"
                params.append(f"%{path_contains}%")
            sql += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def host_context(self, scope_name: str, host: str) -> dict | None:
        """Per-host detail for chat focus. Returns None if the host is not
        an in-scope domain of this app."""
        host = (host or "").strip().lower()
        if not host:
            return None
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            row = conn.execute(
                "SELECT id FROM domains WHERE app_id = ? AND host = ? AND in_scope = 1",
                (app_id, host),
            ).fetchone()
            if not row:
                return None
            endpoints = conn.execute(
                """
                SELECT method, host, path, normalized_path, feature, risk_score, seen_count, last_seen
                FROM endpoints WHERE app_id = ? AND host = ?
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT 40
                """,
                (app_id, host),
            ).fetchall()
            pages = conn.execute(
                "SELECT host, path, title, last_seen FROM page_titles WHERE app_id = ? AND host = ? ORDER BY last_seen DESC LIMIT 10",
                (app_id, host),
            ).fetchall()
            return {
                "host": host,
                "endpoint_count": len(endpoints),
                "endpoints": [dict(x) for x in endpoints],
                "recent_pages": [dict(x) for x in pages],
            }

    def most_recent_host(self, scope_name: str) -> str | None:
        """Host of the most recently viewed in-scope page (fallback: most
        recently seen endpoint host)."""
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            row = conn.execute(
                """
                SELECT host FROM page_titles
                WHERE app_id = ?
                  AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY last_seen DESC LIMIT 1
                """,
                (app_id, app_id),
            ).fetchone()
            if row:
                return row["host"]
            row = conn.execute(
                """
                SELECT host FROM endpoints
                WHERE app_id = ?
                  AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY last_seen DESC LIMIT 1
                """,
                (app_id, app_id),
            ).fetchone()
            return row["host"] if row else None

    def list_scopes(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    a.id,
                    a.name,
                    a.updated_at,
                    COUNT(e.id) AS endpoint_count,
                    COUNT(DISTINCT d.host) AS host_count
                FROM apps a
                LEFT JOIN endpoints e ON e.app_id = a.id
                    AND e.host IN (SELECT host FROM domains WHERE app_id = a.id AND in_scope = 1)
                LEFT JOIN domains d ON d.app_id = a.id AND d.in_scope = 1
                GROUP BY a.id
                ORDER BY a.updated_at DESC
                """
            ).fetchall()
            return [
                {
                    "id": int(r["id"]),
                    "name": r["name"],
                    "updated_at": r["updated_at"],
                    "endpoint_count": int(r["endpoint_count"]),
                    "host_count": int(r["host_count"]),
                }
                for r in rows
            ]

    def record_domain(self, scope_name: str, host: str, classification: str, confidence: str = "medium") -> None:
        if not host:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            conn.execute(
                """
                INSERT INTO domains(app_id, host, classification, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_id, host) DO UPDATE SET
                    classification = excluded.classification,
                    confidence = excluded.confidence,
                    last_seen = excluded.last_seen
                """,
                (app_id, host, classification, confidence, now, now),
            )

    def record_relationship(self, scope_name: str, rel: dict) -> None:
        if not rel:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            conn.execute(
                """
                INSERT INTO domain_relationships(app_id, source_host, target_host, relationship_type, evidence, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_id, source_host, target_host, relationship_type)
                DO UPDATE SET evidence = excluded.evidence, confidence = excluded.confidence
                """,
                (
                    app_id,
                    rel.get("source", ""),
                    rel.get("target", ""),
                    rel.get("relationship_type", ""),
                    json.dumps(rel.get("evidence", [])),
                    rel.get("confidence", "medium"),
                ),
            )

    def record_endpoint(
        self,
        scope_name: str,
        *,
        method: str,
        host: str,
        path: str,
        normalized_path: str,
        query_params: list[str],
        content_type: str,
        auth_observed: bool,
        source_tool: str,
        feature: str,
        workflow: str,
        risk_score: int,
        notes: str = "",
    ) -> bool:
        """Record endpoint and return True if this is a new endpoint."""
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            row = conn.execute(
                "SELECT id, seen_count, risk_score, auth_observed FROM endpoints WHERE app_id = ? AND method = ? AND host = ? AND normalized_path = ?",
                (app_id, method, host, normalized_path),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE endpoints SET
                        path = ?,
                        query_params = ?,
                        content_type = ?,
                        auth_observed = ?,
                        last_seen = ?,
                        source_tool = ?,
                        feature = ?,
                        workflow = ?,
                        risk_score = ?,
                        seen_count = ?,
                        notes = ?
                    WHERE id = ?
                    """,
                    (
                        path,
                        json.dumps(query_params),
                        content_type,
                        int(auth_observed or row["auth_observed"]),
                        now,
                        source_tool,
                        feature,
                        workflow,
                        max(int(row["risk_score"]), risk_score),
                        int(row["seen_count"]) + 1,
                        notes,
                        int(row["id"]),
                    ),
                )
                return False

            conn.execute(
                """
                INSERT INTO endpoints(
                    app_id, method, host, path, normalized_path, query_params, content_type,
                    auth_observed, source_tool, first_seen, last_seen, feature, workflow, risk_score, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    method,
                    host,
                    path,
                    normalized_path,
                    json.dumps(query_params),
                    content_type,
                    int(auth_observed),
                    source_tool,
                    now,
                    now,
                    feature,
                    workflow,
                    risk_score,
                    notes,
                ),
            )
            return True

    def record_business_objects(self, scope_name: str, object_names: list[str]) -> None:
        if not object_names:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            for name in sorted(set(x for x in object_names if x)):
                conn.execute(
                    """
                    INSERT INTO business_objects(app_id, name)
                    VALUES (?, ?)
                    ON CONFLICT(app_id, name) DO NOTHING
                    """,
                    (app_id, name),
                )

    def record_role(self, scope_name: str, role_name: str) -> None:
        if not role_name:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            conn.execute(
                "INSERT INTO roles(app_id, role_name) VALUES (?, ?) ON CONFLICT(app_id, role_name) DO NOTHING",
                (app_id, role_name.strip().lower()),
            )

    def record_discovered_routes(self, scope_name: str, routes: list[dict]) -> int:
        if not routes:
            return 0
        inserted = 0
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            for route in routes:
                cur = conn.execute(
                    """
                    INSERT INTO discovered_routes(app_id, route, route_type, host, normalized_path)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(app_id, route) DO NOTHING
                    """,
                    (
                        app_id,
                        route.get("route", ""),
                        route.get("route_type", "api"),
                        route.get("host"),
                        route.get("normalized_path", route.get("route", "")),
                    ),
                )
                if cur.rowcount == 1:
                    inserted += 1
        return inserted

    def mark_route_observed(self, scope_name: str, normalized_path: str) -> None:
        if not normalized_path:
            return
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            conn.execute(
                "UPDATE discovered_routes SET observed_in_proxy = 1 WHERE app_id = ? AND normalized_path = ?",
                (app_id, normalized_path),
            )

    def record_js_findings(self, scope_name: str, source_host: str, source_path: str, findings: list[dict]) -> int:
        if not findings:
            return 0
        inserted = 0
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            for f in findings:
                finding_type = str(f.get("finding_type", "")).strip().lower() or "unknown"
                category = str(f.get("category", "")).strip().lower() or "unknown"
                indicator = str(f.get("indicator", "")).strip()
                if not indicator:
                    continue
                confidence = str(f.get("confidence", "medium")).strip().lower() or "medium"
                evidence = str(f.get("evidence", "")).strip()

                row = conn.execute(
                    """
                    SELECT id, seen_count FROM js_findings
                    WHERE app_id = ? AND source_host = ? AND source_path = ?
                    AND finding_type = ? AND category = ? AND indicator = ?
                    """,
                    (app_id, source_host or "", source_path or "", finding_type, category, indicator),
                ).fetchone()
                if row:
                    conn.execute(
                        """
                        UPDATE js_findings
                        SET last_seen = ?, seen_count = ?, confidence = ?, evidence = ?
                        WHERE id = ?
                        """,
                        (now, int(row["seen_count"]) + 1, confidence, evidence, int(row["id"])),
                    )
                    continue

                conn.execute(
                    """
                    INSERT INTO js_findings(
                        app_id, source_host, source_path, finding_type, category, indicator,
                        confidence, evidence, first_seen, last_seen, seen_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        app_id,
                        source_host or "",
                        source_path or "",
                        finding_type,
                        category,
                        indicator,
                        confidence,
                        evidence,
                        now,
                        now,
                    ),
                )
                inserted += 1
        return inserted

    def upsert_quest(self, scope_name: str, quest: dict) -> int:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            row = conn.execute(
                "SELECT id FROM quests WHERE app_id = ? AND name = ?",
                (app_id, quest["name"]),
            ).fetchone()
            if row:
                quest_id = int(row["id"])
                conn.execute(
                    "UPDATE quests SET reason = ?, updated_at = ? WHERE id = ?",
                    (quest.get("reason", ""), now, quest_id),
                )
                conn.execute("DELETE FROM quest_tasks WHERE quest_id = ?", (quest_id,))
            else:
                cur = conn.execute(
                    "INSERT INTO quests(app_id, name, reason, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (app_id, quest["name"], quest.get("reason", ""), now, now),
                )
                quest_id = int(cur.lastrowid)

            for task in quest.get("tasks", []):
                conn.execute(
                    """
                    INSERT INTO quest_tasks(quest_id, description, status, related_endpoint, evidence_id, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        quest_id,
                        task.get("description", ""),
                        task.get("status", "todo"),
                        task.get("related_endpoint", ""),
                        task.get("evidence_id", ""),
                        task.get("notes", ""),
                    ),
                )
            return quest_id

    def list_quests(self, scope_name: str) -> list[dict]:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            quests = conn.execute(
                "SELECT id, name, reason, status, created_at, updated_at FROM quests WHERE app_id = ? ORDER BY id",
                (app_id,),
            ).fetchall()
            out = []
            for q in quests:
                tasks = conn.execute(
                    "SELECT id, description, status, related_endpoint, evidence_id, notes FROM quest_tasks WHERE quest_id = ? ORDER BY id",
                    (int(q["id"]),),
                ).fetchall()
                out.append(
                    {
                        "id": int(q["id"]),
                        "name": q["name"],
                        "reason": q["reason"],
                        "status": q["status"],
                        "created_at": q["created_at"],
                        "updated_at": q["updated_at"],
                        "tasks": [
                            {
                                "id": int(t["id"]),
                                "description": t["description"],
                                "status": t["status"],
                                "related_endpoint": t["related_endpoint"],
                                "evidence_id": t["evidence_id"],
                                "notes": t["notes"],
                            }
                            for t in tasks
                        ],
                    }
                )
            return out

    def complete_task(self, scope_name: str, quest_id: int, task_id: int) -> bool:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            row = conn.execute("SELECT id FROM quests WHERE id = ? AND app_id = ?", (quest_id, app_id)).fetchone()
            if not row:
                return False
            cur = conn.execute(
                "UPDATE quest_tasks SET status = 'done' WHERE id = ? AND quest_id = ?",
                (task_id, quest_id),
            )
            if cur.rowcount == 0:
                return False

            pending = conn.execute(
                "SELECT COUNT(*) AS cnt FROM quest_tasks WHERE quest_id = ? AND status != 'done'",
                (quest_id,),
            ).fetchone()["cnt"]
            status = "done" if int(pending) == 0 else "in_progress"
            conn.execute(
                "UPDATE quests SET status = ?, updated_at = ? WHERE id = ?",
                (status, self._now(), quest_id),
            )
            return True

    def save_evidence(
        self,
        scope_name: str,
        title: str,
        category: str,
        endpoint: str,
        request: str,
        response: str,
        notes: str,
        confidence: str,
    ) -> str:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            cur = conn.execute(
                """
                INSERT INTO evidence(app_id, title, category, endpoint, request, response, notes, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (app_id, title, category, endpoint, request, response, notes, confidence, self._now()),
            )
            return f"ev_{int(cur.lastrowid):03d}"

    def record_redirect(
        self,
        scope_name: str,
        source_host: str,
        source_path: str,
        status_code: int,
        location: str,
    ) -> None:
        if not source_host or not source_path or not status_code or not location:
            return
        try:
            target_host = (urlparse(location).hostname or "").lower()
        except ValueError:
            target_host = ""

        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            now = self._now()
            row = conn.execute(
                """
                SELECT id, seen_count FROM redirect_events
                WHERE app_id = ? AND source_host = ? AND source_path = ? AND status_code = ? AND location = ?
                """,
                (app_id, source_host, source_path, status_code, location),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE redirect_events
                    SET last_seen = ?, seen_count = ?
                    WHERE id = ?
                    """,
                    (now, int(row["seen_count"]) + 1, int(row["id"])),
                )
                return

            conn.execute(
                """
                INSERT INTO redirect_events(
                    app_id, source_host, source_path, status_code, location, target_host, first_seen, last_seen, seen_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (app_id, source_host, source_path, status_code, location, target_host, now, now),
            )

    def app_snapshot(self, scope_name: str) -> dict:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            endpoints = conn.execute(
                "SELECT method, host, path, normalized_path, feature, workflow, risk_score, auth_observed FROM endpoints WHERE app_id = ? "
                "AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)",
                (app_id, app_id),
            ).fetchall()
            discovered_routes = conn.execute(
                "SELECT route, route_type, host, normalized_path, observed_in_proxy FROM discovered_routes WHERE app_id = ? "
                "AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)",
                (app_id, app_id),
            ).fetchall()
            objects = conn.execute(
                "SELECT name FROM business_objects WHERE app_id = ? ORDER BY name",
                (app_id,),
            ).fetchall()
            redirects = conn.execute(
                "SELECT source_host, source_path, status_code, location, target_host, seen_count FROM redirect_events WHERE app_id = ? "
                "AND source_host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1) ORDER BY last_seen DESC",
                (app_id, app_id),
            ).fetchall()
            js_findings = conn.execute(
                """
                SELECT source_host, source_path, finding_type, category, indicator, confidence, evidence, seen_count
                FROM js_findings
                WHERE app_id = ?
                  AND source_host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY seen_count DESC, id DESC
                """,
                (app_id, app_id),
            ).fetchall()
            return {
                "endpoints": [dict(x) for x in endpoints],
                "discovered_routes": [dict(x) for x in discovered_routes],
                "business_objects": [x["name"] for x in objects],
                "redirect_events": [dict(x) for x in redirects],
                "js_findings": [dict(x) for x in js_findings],
            }

    def summary(self, scope_name: str) -> dict:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            domains = conn.execute(
                "SELECT host, classification FROM domains WHERE app_id = ? AND in_scope = 1 ORDER BY host",
                (app_id,),
            ).fetchall()
            endpoints = conn.execute(
                "SELECT method, host, normalized_path, feature, risk_score FROM endpoints WHERE app_id = ? "
                "AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1) "
                "ORDER BY risk_score DESC",
                (app_id, app_id),
            ).fetchall()
            objects = conn.execute(
                "SELECT name FROM business_objects WHERE app_id = ? ORDER BY name",
                (app_id,),
            ).fetchall()
            roles = conn.execute(
                "SELECT role_name FROM roles WHERE app_id = ? ORDER BY role_name",
                (app_id,),
            ).fetchall()
            unobserved = conn.execute(
                "SELECT route FROM discovered_routes WHERE app_id = ? AND observed_in_proxy = 0 "
                "AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1) ORDER BY route",
                (app_id, app_id),
            ).fetchall()
            redirects = conn.execute(
                "SELECT target_host FROM redirect_events WHERE app_id = ? "
                "AND source_host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1) ORDER BY id",
                (app_id, app_id),
            ).fetchall()
            js_findings = conn.execute(
                """
                SELECT finding_type, category, indicator, source_host, source_path
                FROM js_findings
                WHERE app_id = ?
                  AND source_host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY seen_count DESC, id DESC
                """,
                (app_id, app_id),
            ).fetchall()

            recent_pages = conn.execute(
                """
                SELECT host, path, title, last_seen
                FROM page_titles
                WHERE app_id = ?
                  AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY last_seen DESC
                LIMIT 20
                """,
                (app_id, app_id),
            ).fetchall()
            recent_endpoints = conn.execute(
                """
                SELECT method, host, path, last_seen
                FROM endpoints
                WHERE app_id = ?
                  AND host IN (SELECT host FROM domains WHERE app_id = ? AND in_scope = 1)
                ORDER BY last_seen DESC
                LIMIT 15
                """,
                (app_id, app_id),
            ).fetchall()

            frontend_hosts = [d["host"] for d in domains if d["classification"] == "frontend"]
            likely_api_hosts = [
                d["host"]
                for d in domains
                if d["classification"] in {"likely_first_party_api", "auth", "graphql", "websocket"}
            ]
            third_party_hosts = [d["host"] for d in domains if d["classification"] == "third_party"]

            features = sorted({e["feature"] for e in endpoints if e["feature"] and e["feature"] != "unknown"})
            important_objects = [o["name"] for o in objects]
            likely_roles = [r["role_name"] for r in roles]

            highest_value_tests = []
            for e in endpoints[:20]:
                p = e["normalized_path"]
                if "{id}" in p and not any("IDOR" in t for t in highest_value_tests):
                    highest_value_tests.append("project IDOR")
                if any(x in p for x in ("tenant", "org", "account")) and "tenant boundary bypass" not in highest_value_tests:
                    highest_value_tests.append("tenant boundary bypass")
                if any(x in p for x in ("role", "permission", "member")) and "role escalation" not in highest_value_tests:
                    highest_value_tests.append("role escalation")
                if "invite" in p and "invite token abuse" not in highest_value_tests:
                    highest_value_tests.append("invite token abuse")
                if any(x in p for x in ("billing", "payment", "subscription")) and "billing tampering" not in highest_value_tests:
                    highest_value_tests.append("billing tampering")
                if len(highest_value_tests) >= 5:
                    break

            untested = []
            if any("export" in e["normalized_path"] for e in endpoints):
                untested.append("export endpoints")
            if unobserved:
                untested.append("admin/internal routes discovered in JavaScript")
            if any("mfa" in e["normalized_path"] for e in endpoints):
                untested.append("MFA challenge endpoints")
            if redirects:
                untested.append("redirect chain and open-redirect validation")

            js_secret_findings = []
            js_hidden_endpoints = []
            js_obfuscation_signals = []
            for finding in js_findings:
                f_type = finding["finding_type"]
                category = finding["category"]
                indicator = finding["indicator"]
                source_host = finding["source_host"]
                source_path = finding["source_path"]
                source = f"{source_host}{source_path}" if (source_host or source_path) else "javascript"
                if f_type == "secret":
                    js_secret_findings.append(f"{category}: {indicator} ({source})")
                elif f_type == "endpoint":
                    js_hidden_endpoints.append(indicator)
                elif f_type == "obfuscation":
                    js_obfuscation_signals.append(indicator)

            if js_secret_findings and "hardcoded secrets in JavaScript" not in highest_value_tests:
                highest_value_tests.insert(0, "hardcoded secrets in JavaScript")
            if js_hidden_endpoints and "hidden JavaScript endpoints not exercised in proxy" not in highest_value_tests:
                highest_value_tests.append("hidden JavaScript endpoints not exercised in proxy")
            if js_secret_findings and "javascript hardcoded secrets review" not in untested:
                untested.append("javascript hardcoded secrets review")
            if js_obfuscation_signals and "deobfuscate/high-risk JS bundle review" not in untested:
                untested.append("deobfuscate/high-risk JS bundle review")

            if not domains and not endpoints:
                app_summary = (
                    "No traffic has been analyzed yet for this scope. "
                    "Capture requests in Burp and sync/import them to Sentinel."
                )
            elif features:
                app_summary = (
                    "This appears to be an application with features around "
                    + ", ".join(features[:5])
                    + "."
                )
                if js_secret_findings:
                    app_summary += " JavaScript bundles include potential hardcoded secrets that should be validated."
            else:
                app_summary = (
                    "Traffic has been observed, but feature inference is still low confidence. "
                    "Capture more authenticated workflows for better summaries."
                )
                if js_hidden_endpoints:
                    app_summary += " JavaScript also references additional hidden endpoints."

            return {
                "app_summary": app_summary,
                "frontend_hosts": frontend_hosts,
                "likely_api_hosts": likely_api_hosts,
                "third_party_hosts": third_party_hosts,
                "observed_features": features,
                "important_objects": important_objects,
                "likely_roles": likely_roles,
                "highest_value_tests": highest_value_tests,
                "untested_areas": untested,
                "javascript_findings_count": len(js_findings),
                "javascript_secret_findings": js_secret_findings[:20],
                "javascript_hidden_endpoints": sorted(set(js_hidden_endpoints))[:30],
                "javascript_obfuscation_signals": sorted(set(js_obfuscation_signals))[:20],
                "redirect_count": len(redirects),
                "redirect_targets": sorted({r["target_host"] for r in redirects if r["target_host"]}),
                "recent_pages": [dict(x) for x in recent_pages],
                "recent_endpoints": [dict(x) for x in recent_endpoints],
                # Backward-compatible fields from the basic version.
                "observed_hosts": sorted({d["host"] for d in domains}),
                "endpoint_count": len(endpoints),
                "high_value_endpoints": [
                    f"{e['host']} {e['method']} {e['normalized_path']}"
                    for e in endpoints
                    if int(e["risk_score"] or 0) >= 4
                ][:10],
            }

    def proxy_import_stats(self, scope_name: str) -> dict:
        with self._lock, self._conn() as conn:
            app_id = self._app_id(conn, scope_name)
            domains_discovered = conn.execute(
                "SELECT COUNT(*) AS cnt FROM domains WHERE app_id = ?",
                (app_id,),
            ).fetchone()["cnt"]
            api_hosts_discovered = conn.execute(
                """
                SELECT COUNT(*) AS cnt FROM domains
                WHERE app_id = ? AND classification IN ('likely_first_party_api', 'auth', 'graphql')
                """,
                (app_id,),
            ).fetchone()["cnt"]
            return {
                "domains_discovered": int(domains_discovered),
                "api_hosts_discovered": int(api_hosts_discovered),
            }


def _default_db_path() -> str:
    env = os.getenv("SENTINEL_DB_PATH", "").strip()
    if env:
        return env
    return os.path.join(os.path.dirname(__file__), "data", "sentinel.sqlite")


store = Store(_default_db_path())
