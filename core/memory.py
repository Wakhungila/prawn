#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Persistent agent memory and prioritization for PIN0CCHI0

This module provides a SQLite-backed MemoryStore and a high-level AgentContext
that the engine can use to:
- Remember past scans per target (URLs/endpoints, parameters, tool results)
- Track anomalies/failures and false positives
- Maintain payload outcome statistics and WAF signatures
- Prioritize what to test next (endpoints/modules) across runs

Design principles:
- Append-only journaling for evidence and failures
- Keep structured fields in columns and flexible artifacts in JSON
- Avoid per-run in-memory state duplication; prefer persisted state
- Be resilient to schema evolutions via simple migrations
"""

from __future__ import annotations

import os
import json
import time
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

_DEFAULT_DB = os.path.join('memory', 'pin0cchi0.sqlite3')

_SCHEMA = [
    # Targets catalog
    """
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE NOT NULL,
        first_seen_ts REAL NOT NULL,
        last_seen_ts REAL NOT NULL
    );
    """,
    # Scans (per target)
    """
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target_id INTEGER NOT NULL,
        started_ts REAL NOT NULL,
        ended_ts REAL,
        config_json TEXT,
        status TEXT,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # Endpoints discovered/observed
    """
    CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        method TEXT,
        params_json TEXT,
        meta_json TEXT,
        first_seen_ts REAL NOT NULL,
        last_seen_ts REAL NOT NULL,
        UNIQUE(target_id, url, method),
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # Module tests/findings evidence
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        scan_id TEXT,
        module TEXT NOT NULL,
        url TEXT,
        params_json TEXT,
        severity TEXT,
        type TEXT,
        title TEXT,
        evidence_json TEXT,
        timestamp REAL NOT NULL,
        is_false_positive INTEGER DEFAULT 0,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # Anomalies for prioritization (e.g., suspect responses)
    """
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        scan_id TEXT,
        url TEXT NOT NULL,
        description TEXT,
        score REAL DEFAULT 0,
        meta_json TEXT,
        timestamp REAL NOT NULL,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # Failures/errors for active learning and triage
    """
    CREATE TABLE IF NOT EXISTS failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        scan_id TEXT,
        module TEXT NOT NULL,
        url TEXT,
        reason TEXT,
        error_code TEXT,
        raw_json TEXT,
        timestamp REAL NOT NULL,
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # Payload statistics and WAF signature hints
    """
    CREATE TABLE IF NOT EXISTS payload_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER NOT NULL,
        context TEXT,            -- e.g., sqli|xss|idor
        payload_key TEXT NOT NULL,  -- key in library (hash/name)
        waf_signature TEXT,       -- e.g., cloudflare|modsec|custom:403pattern
        success_count INTEGER DEFAULT 0,
        failure_count INTEGER DEFAULT 0,
        blocked_count INTEGER DEFAULT 0,
        avg_latency_ms REAL,
        last_outcome TEXT,
        last_ts REAL,
        UNIQUE(target_id, context, payload_key, IFNULL(waf_signature, '')),
        FOREIGN KEY (target_id) REFERENCES targets(id)
    );
    """,
    # False positive notes to learn from reviewer decisions
    """
    CREATE TABLE IF NOT EXISTS false_positives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL,
        reason TEXT,
        timestamp REAL NOT NULL,
        FOREIGN KEY (finding_id) REFERENCES findings(id)
    );
    """,
]

class MemoryStore:
    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            cur = self._conn.cursor()
            for stmt in _SCHEMA:
                cur.execute(stmt)

    # --- Helpers ---
    def _now(self) -> float:
        return time.time()

    def _get_target_id(self, target: str) -> int:
        t = target.strip()
        with self._conn:
            cur = self._conn.cursor()
            cur.execute("SELECT id FROM targets WHERE target=?", (t,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE targets SET last_seen_ts=? WHERE id=?", (self._now(), row[0]))
                return int(row[0])
            cur.execute(
                "INSERT INTO targets (target, first_seen_ts, last_seen_ts) VALUES (?, ?, ?)",
                (t, self._now(), self._now())
            )
            return int(cur.lastrowid)

    # --- Public API ---
    def record_scan(self, target: str, scan_id: str, config: Optional[Dict[str, Any]] = None, status: str = 'started') -> int:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO scans (scan_id, target_id, started_ts, config_json, status) VALUES (?, ?, ?, ?, ?)",
                (scan_id, tid, self._now(), json.dumps(config or {}, ensure_ascii=False), status)
            )
            return int(cur.lastrowid)

    def end_scan(self, target: str, scan_id: str, status: str = 'completed') -> None:
        tid = self._get_target_id(target)
        with self._conn:
            self._conn.execute(
                "UPDATE scans SET ended_ts=?, status=? WHERE target_id=? AND scan_id=?",
                (self._now(), status, tid, scan_id)
            )

    def add_endpoint(self, target: str, url: str, method: str = 'GET', params: Optional[Dict[str, Any]] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT id FROM endpoints WHERE target_id=? AND url=? AND IFNULL(method,'')=IFNULL(?, '')",
                (tid, url, method)
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE endpoints SET params_json=?, meta_json=?, last_seen_ts=? WHERE id=?",
                    (json.dumps(params or {}), json.dumps(meta or {}), self._now(), int(row[0]))
                )
            else:
                cur.execute(
                    "INSERT INTO endpoints (target_id, url, method, params_json, meta_json, first_seen_ts, last_seen_ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tid, url, method, json.dumps(params or {}), json.dumps(meta or {}), self._now(), self._now())
                )

    def record_finding(self, target: str, scan_id: str, module: str, url: Optional[str], params: Optional[Dict[str, Any]], severity: str, ftype: str, title: str, evidence: Optional[Dict[str, Any]]) -> int:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO findings (target_id, scan_id, module, url, params_json, severity, type, title, evidence_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tid, scan_id, module, url, json.dumps(params or {}), severity, ftype, title, json.dumps(evidence or {}), self._now())
            )
            return int(cur.lastrowid)

    def mark_false_positive(self, finding_id: int, reason: str) -> None:
        with self._conn:
            self._conn.execute("UPDATE findings SET is_false_positive=1 WHERE id=?", (finding_id,))
            self._conn.execute(
                "INSERT INTO false_positives (finding_id, reason, timestamp) VALUES (?, ?, ?)",
                (finding_id, reason, self._now())
            )

    def record_anomaly(self, target: str, scan_id: str, url: str, description: str, score: float = 0.5, meta: Optional[Dict[str, Any]] = None) -> int:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO anomalies (target_id, scan_id, url, description, score, meta_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tid, scan_id, url, description, score, json.dumps(meta or {}), self._now())
            )
            return int(cur.lastrowid)

    def record_failure(self, target: str, scan_id: str, module: str, url: Optional[str], reason: str, error_code: Optional[str] = None, raw: Optional[Dict[str, Any]] = None) -> int:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO failures (target_id, scan_id, module, url, reason, error_code, raw_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (tid, scan_id, module, url, reason, error_code, json.dumps(raw or {}), self._now())
            )
            return int(cur.lastrowid)

    def record_payload_outcome(self, target: str, context: str, payload_key: str, success: bool, waf_signature: Optional[str] = None, latency_ms: Optional[float] = None, last_outcome: Optional[str] = None) -> None:
        tid = self._get_target_id(target)
        with self._conn:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT id, success_count, failure_count, blocked_count FROM payload_stats WHERE target_id=? AND context=? AND payload_key=? AND IFNULL(waf_signature,'')=IFNULL(?, '')",
                (tid, context, payload_key, waf_signature)
            )
            row = cur.fetchone()
            if row:
                sid = int(row[0])
                succ = int(row[1]) + (1 if success else 0)
                fail = int(row[2]) + (0 if success else 1)
                blocked = int(row[3])
                if (last_outcome or '').lower() == 'blocked':
                    blocked += 1
                cur.execute(
                    "UPDATE payload_stats SET success_count=?, failure_count=?, blocked_count=?, avg_latency_ms=COALESCE((avg_latency_ms + ?)/2, ?), last_outcome=?, last_ts=? WHERE id=?",
                    (succ, fail, blocked, latency_ms, latency_ms, last_outcome or ('success' if success else 'failure'), self._now(), sid)
                )
            else:
                cur.execute(
                    """
                    INSERT INTO payload_stats (target_id, context, payload_key, waf_signature, success_count, failure_count, blocked_count, avg_latency_ms, last_outcome, last_ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (tid, context, payload_key, waf_signature, 1 if success else 0, 0 if success else 1, 1 if (last_outcome or '').lower()=='blocked' else 0, latency_ms, last_outcome or ('success' if success else 'failure'), self._now())
                )

    # --- Queries / Prioritization ---
    def get_recent_scans(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        tid = self._get_target_id(target)
        cur = self._conn.cursor()
        cur.execute("SELECT scan_id, started_ts, ended_ts, status FROM scans WHERE target_id=? ORDER BY started_ts DESC LIMIT ?", (tid, limit))
        return [dict(r) for r in cur.fetchall()]

    def get_endpoints(self, target: str) -> List[Dict[str, Any]]:
        tid = self._get_target_id(target)
        cur = self._conn.cursor()
        cur.execute("SELECT url, method, params_json, meta_json, first_seen_ts, last_seen_ts FROM endpoints WHERE target_id=? ORDER BY last_seen_ts DESC", (tid,))
        out = []
        for r in cur.fetchall():
            out.append({
                'url': r['url'],
                'method': r['method'] or 'GET',
                'params': json.loads(r['params_json'] or '{}'),
                'meta': json.loads(r['meta_json'] or '{}'),
                'first_seen_ts': r['first_seen_ts'],
                'last_seen_ts': r['last_seen_ts'],
            })
        return out

    def get_prioritized_queue(self, target: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Build a prioritized queue of endpoints to test next, ranking by:
        - Anomaly score (higher first)
        - Recency of anomalies and findings
        - Lack of coverage (few tests recorded)
        """
        tid = self._get_target_id(target)
        cur = self._conn.cursor()
        # Aggregate by URL for anomalies
        cur.execute(
            """
            SELECT a.url, MAX(a.score) AS max_score, MAX(a.timestamp) AS last_ts
            FROM anomalies a
            WHERE a.target_id=?
            GROUP BY a.url
            ORDER BY max_score DESC, last_ts DESC
            LIMIT ?
            """,
            (tid, limit)
        )
        pri_urls = {row['url']: {'score': row['max_score'], 'last_ts': row['last_ts']} for row in cur.fetchall()}
        # Endpoints fallback if no anomalies
        eps = self.get_endpoints(target)
        # Coverage estimation per URL
        cov = {}
        cur.execute("SELECT url, COUNT(*) AS c FROM findings WHERE target_id=? GROUP BY url", (tid,))
        for r in cur.fetchall():
            cov[r['url']] = r['c']
        # Build queue
        items = []
        for e in eps:
            url = e['url']
            score = pri_urls.get(url, {}).get('score', 0.0)
            coverage = cov.get(url, 0)
            items.append({
                'url': url,
                'method': e['method'],
                'params': e['params'],
                'score': score,
                'coverage': coverage,
                'priority': (score * 2.0) + (0 if coverage > 0 else 1.0)
            })
        items.sort(key=lambda x: (-x['priority'], -x['score'], x['coverage']))
        return items[:limit]

    def get_payload_candidates(self, target: str, context: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Return payload keys and stats ranked by success and low block rates."""
        tid = self._get_target_id(target)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT payload_key, waf_signature, success_count, failure_count, blocked_count, avg_latency_ms, last_outcome, last_ts
            FROM payload_stats
            WHERE target_id=? AND context=?
            ORDER BY (success_count - failure_count - blocked_count) DESC, last_ts DESC
            LIMIT ?
            """,
            (tid, context, limit)
        )
        out = []
        for r in cur.fetchall():
            out.append({
                'payload_key': r['payload_key'],
                'waf_signature': r['waf_signature'],
                'success_count': r['success_count'],
                'failure_count': r['failure_count'],
                'blocked_count': r['blocked_count'],
                'avg_latency_ms': r['avg_latency_ms'],
                'last_outcome': r['last_outcome'],
                'last_ts': r['last_ts'],
            })
        return out

class AgentContext:
    """High-level helper to drive planning and adaptive payload selection."""
    def __init__(self, store: Optional[MemoryStore] = None):
        self.store = store or MemoryStore()

    def remember_endpoints(self, target: str, discovered: List[str]) -> None:
        for u in discovered or []:
            try:
                self.store.add_endpoint(target, u, method='GET', params=None, meta={'source': 'crawler'})
            except Exception:
                pass

    def record_findings_bulk(self, target: str, scan_id: str, findings: List[Dict[str, Any]]) -> None:
        for f in findings or []:
            try:
                self.store.record_finding(
                    target=target,
                    scan_id=scan_id,
                    module=f.get('module') or f.get('source') or 'unknown',
                    url=f.get('url'),
                    params=f.get('params'),
                    severity=f.get('severity', 'Info'),
                    ftype=f.get('type', 'Finding'),
                    title=f.get('title', f.get('type', 'Finding')),
                    evidence=f.get('evidence')
                )
            except Exception:
                pass

    def prioritize(self, target: str, limits: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.store.get_prioritized_queue(target, limit=(limits or {}).get('limit', 50))

    def note_failure(self, target: str, scan_id: str, module: str, url: Optional[str], reason: str, error_code: Optional[str] = None, raw: Optional[Dict[str, Any]] = None) -> None:
        self.store.record_failure(target, scan_id, module, url, reason, error_code, raw)

    def note_anomaly(self, target: str, scan_id: str, url: str, description: str, score: float = 0.5, meta: Optional[Dict[str, Any]] = None) -> None:
        self.store.record_anomaly(target, scan_id, url, description, score, meta)

    def choose_payloads(self, target: str, context: str, hints: Optional[Dict[str, Any]] = None, limit: int = 12) -> List[str]:
        """
        Return ordered payload keys (from library) based on prior success and WAF hints.
        """
        stats = self.store.get_payload_candidates(target, context, limit=limit)
        keys = [s['payload_key'] for s in stats]
        # If no historical stats, rely on an initial default ordering (to be provided by payload lib).
        if not keys:
            # Basic defaults per context
            defaults = {
                'sqli': ['sqli:boolean:or1eq1', 'sqli:comment:inline', 'sqli:time:mysql'],
                'xss': ['xss:reflected:basic', 'xss:attr:onerror', 'xss:svg:onload'],
                'idor': ['idor:numeric:inc', 'idor:numeric:dec'],
            }
            keys = defaults.get(context, [])
        return keys[:limit]

    def learn_payload_outcome(self, target: str, context: str, payload_key: str, success: bool, waf_signature: Optional[str] = None, latency_ms: Optional[float] = None, last_outcome: Optional[str] = None) -> None:
        self.store.record_payload_outcome(target, context, payload_key, success, waf_signature, latency_ms, last_outcome)

    def start_scan(self, target: str, scan_id: str, config: Optional[Dict[str, Any]] = None) -> None:
        self.store.record_scan(target, scan_id, config, status='running')

    def end_scan(self, target: str, scan_id: str, status: str = 'completed') -> None:
        self.store.end_scan(target, scan_id, status)

# Convenience singleton for modules that want a default memory layer without wiring
_global_store: Optional[MemoryStore] = None
_global_store_lock = threading.Lock()

def get_global_store() -> MemoryStore:
    global _global_store
    if _global_store is None:
        with _global_store_lock:
            if _global_store is None:
                _global_store = MemoryStore()
    return _global_store
