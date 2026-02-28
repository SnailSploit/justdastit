"""justdastit - SQLite project database for history, findings, and state."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Optional

from .models import (
    Finding,
    HttpRequest,
    HttpResponse,
    RequestResponse,
    Severity,
)

__all__ = ["ProjectDB"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    headers TEXT,
    body BLOB,
    timestamp REAL,
    content_hash TEXT,
    tags TEXT DEFAULT '[]',
    notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    headers TEXT,
    body BLOB,
    elapsed_ms REAL,
    timestamp REAL,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    cwe TEXT,
    remediation TEXT,
    request_id INTEGER,
    timestamp REAL,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS sitemap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    status_code INTEGER,
    content_type TEXT,
    discovered_from TEXT,
    depth INTEGER DEFAULT 0,
    timestamp REAL
);

CREATE TABLE IF NOT EXISTS forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    action TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    inputs TEXT DEFAULT '[]',
    found_on TEXT,
    timestamp REAL
);

CREATE INDEX IF NOT EXISTS idx_requests_url ON requests(url);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_sitemap_url ON sitemap(url);
CREATE INDEX IF NOT EXISTS idx_forms_url ON forms(url);
"""


class ProjectDB:
    """SQLite-backed project database."""

    def __init__(self, db_path: str = "justdastit.db") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def save_request(self, req: HttpRequest, tags: list[str] | None = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO requests (method, url, headers, body, timestamp, content_hash, tags)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                req.method,
                req.url,
                json.dumps(req.headers),
                req.body,
                req.timestamp,
                req.content_hash,
                json.dumps(tags or []),
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def save_response(self, request_id: int, resp: HttpResponse) -> int:
        cur = self.conn.execute(
            """INSERT INTO responses (request_id, status_code, headers, body, elapsed_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                request_id,
                resp.status_code,
                json.dumps(resp.headers),
                resp.body,
                resp.elapsed_ms,
                resp.timestamp,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def save_request_response(
        self, req: HttpRequest, resp: HttpResponse, tags: list[str] | None = None
    ) -> int:
        req_id = self.save_request(req, tags)
        self.save_response(req_id, resp)
        return req_id

    def save_finding(self, finding: Finding, request_id: Optional[int] = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO findings (title, severity, url, detail, evidence, cwe, remediation, request_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.title,
                finding.severity.value,
                finding.url,
                finding.detail,
                finding.evidence,
                finding.cwe,
                finding.remediation,
                request_id,
                finding.timestamp,
            ),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def add_sitemap_url(
        self,
        url: str,
        status_code: Optional[int] = None,
        content_type: str = "",
        discovered_from: str = "",
        depth: int = 0,
    ) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO sitemap (url, status_code, content_type, discovered_from, depth, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (url, status_code, content_type, discovered_from, depth, time.time()),
        )
        self.conn.commit()

    def save_form(
        self,
        url: str,
        action: str,
        method: str = "GET",
        inputs: list[dict] | None = None,
        found_on: str = "",
    ) -> int:
        cur = self.conn.execute(
            """INSERT INTO forms (url, action, method, inputs, found_on, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (url, action, method, json.dumps(inputs or []), found_on, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_requests(
        self, limit: int = 100, offset: int = 0, url_filter: str = ""
    ) -> list[dict]:
        query = "SELECT * FROM requests"
        params: list[object] = []
        if url_filter:
            query += " WHERE url LIKE ?"
            params.append(f"%{url_filter}%")
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self.conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_request_response(self, request_id: int) -> Optional[RequestResponse]:
        req_row = self.conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not req_row:
            return None
        req = HttpRequest(
            method=req_row["method"],
            url=req_row["url"],
            headers=json.loads(req_row["headers"] or "{}"),
            body=req_row["body"],
            timestamp=req_row["timestamp"],
            id=req_row["id"],
        )
        resp_row = self.conn.execute(
            "SELECT * FROM responses WHERE request_id = ? ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        resp = None
        if resp_row:
            resp = HttpResponse(
                status_code=resp_row["status_code"],
                headers=json.loads(resp_row["headers"] or "{}"),
                body=resp_row["body"],
                elapsed_ms=resp_row["elapsed_ms"],
                timestamp=resp_row["timestamp"],
            )
        return RequestResponse(
            request=req,
            response=resp,
            id=request_id,
            tags=json.loads(req_row["tags"] or "[]"),
            notes=req_row["notes"],
        )

    def get_all_request_responses(self, limit: int = 10000) -> list[RequestResponse]:
        """Get all request/response pairs for scanning."""
        rows = self.get_requests(limit=limit)
        results = []
        for row in rows:
            rr = self.get_request_response(row["id"])
            if rr:
                results.append(rr)
        return results

    def get_findings(self, severity: Optional[str] = None) -> list[dict]:
        query = "SELECT * FROM findings"
        params: list[object] = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY id DESC"
        return [dict(r) for r in self.conn.execute(query, params).fetchall()]

    def get_sitemap(self) -> list[dict]:
        return [
            dict(r)
            for r in self.conn.execute("SELECT * FROM sitemap ORDER BY url").fetchall()
        ]

    def get_forms(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM forms ORDER BY id").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["inputs"] = json.loads(d.get("inputs", "[]"))
            result.append(d)
        return result

    def get_sitemap_urls(self) -> list[str]:
        rows = self.conn.execute("SELECT url FROM sitemap ORDER BY url").fetchall()
        return [r["url"] for r in rows]

    def get_stats(self) -> dict:
        reqs = self.conn.execute("SELECT COUNT(*) as c FROM requests").fetchone()["c"]
        findings = self.conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        urls = self.conn.execute("SELECT COUNT(*) as c FROM sitemap").fetchone()["c"]
        forms = self.conn.execute("SELECT COUNT(*) as c FROM forms").fetchone()["c"]
        severity_counts: dict[str, int] = {}
        for row in self.conn.execute(
            "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"
        ).fetchall():
            severity_counts[row["severity"]] = row["c"]
        return {
            "total_requests": reqs,
            "total_findings": findings,
            "sitemap_urls": urls,
            "total_forms": forms,
            "findings_by_severity": severity_counts,
        }

    def clear_findings(self) -> None:
        self.conn.execute("DELETE FROM findings")
        self.conn.commit()

    def reset(self) -> None:
        """Drop all data from every table. Used at autopilot startup to avoid
        stale sitemap/form/finding entries from previous runs."""
        for table in ("requests", "responses", "findings", "sitemap", "forms"):
            self.conn.execute(f"DELETE FROM {table}")  # noqa: S608 — table names are hardcoded
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
