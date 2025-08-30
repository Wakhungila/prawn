#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core Memory and Prioritization Layer for PIN0CCHI0

This module provides a persistent, thread-safe memory store and a simple
prioritizer to enable an autonomous agent loop (perceive -> plan -> act -> learn).

It uses SQLite (stdlib) and avoids external dependencies.

Schema overview:
- scans:        scan metadata and config
- targets:      discovered targets with depth, source, and visited flag
- endpoints:    discovered endpoints with prioritization score and visited flag
- parameters:   parameters discovered per endpoint
- tech:         technology fingerprints per scan/target
- findings:     deduplicated findings with severity, evidence, and module
- artifacts:    paths to saved artifacts (html, screenshots, raw responses)
- actions:      agent actions audit log (module, payload, success)
- signatures:   de-duplication signatures for url+param+payload combos

This layer is intended to be used by Engine in autonomous mode to persist state
across actions, resume, and guide prioritization.
"""

import os
import re
import json
import time
import sqlite3
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

TS_FMT = '%Y-%m-%d %H:%M:%S'

class MemoryStore:
    """SQLite-backed memory store for agent state and results."""

    def __init__(self, db_path: str = 'memory.db'):
        self.db_path = db_path
        self._lock = threading.RLock()
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._init_schema()

    def close(self):
        with self._lock:
            self._conn.close()

    def _init_schema(self):
        cur = self._conn.cursor()
        cur.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT,
                start_time TEXT,
                end_time TEXT,
                config_json TEXT
            );

            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target TEXT,
                depth INTEGER,
                source TEXT,
                first_seen TEXT,
                last_seen TEXT,
                visited INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_targets_scan ON targets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_targets_target ON targets(target);

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target TEXT,
                url TEXT UNIQUE,
                kind TEXT,
                score REAL DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                visited INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
            CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target);
            CREATE INDEX IF NOT EXISTS idx_endpoints_score ON endpoints(score DESC);

            CREATE TABLE IF NOT EXISTS parameters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER,
                name TEXT,
                first_seen TEXT,
                UNIQUE(endpoint_id, name)
            );

            CREATE TABLE IF NOT EXISTS tech (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target TEXT,
                name TEXT,
                version TEXT,
                first_seen TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_tech_scan ON tech(scan_id);

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target TEXT,
                url TEXT,
                type TEXT,
                severity TEXT,
                evidence TEXT,
                module TEXT,
                timestamp TEXT,
                hash TEXT,
                UNIQUE(hash)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                kind TEXT,
                path TEXT,
                metadata_json TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ts TEXT,
                action TEXT,
                module TEXT,
                target TEXT,
                url TEXT,
                payload TEXT,
                success INTEGER,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                signature TEXT UNIQUE,
                first_seen TEXT
            );
            """
        )
        self._conn.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime(TS_FMT)

    # Scans
    def new_scan(self, scan_id: str, target: str, config: Dict[str, Any]):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO scans(id, target, start_time, config_json) VALUES(?,?,?,?)",
                (scan_id, target, self._now(), json.dumps(config or {}))
            )
            self._conn.commit()

    def end_scan(self, scan_id: str):
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET end_time=? WHERE id=?",
                (self._now(), scan_id)
            )
            self._conn.commit()

    # Targets and endpoints
    def add_target(self, scan_id: str, target: str, depth: int = 0, source: str = "seed"):
        with self._lock:
            ts = self._now()
            self._conn.execute(
                "INSERT INTO targets(scan_id, target, depth, source, first_seen, last_seen, visited) VALUES(?,?,?,?,?,?,0)",
                (scan_id, target, depth, source, ts, ts)
            )
            self._conn.commit()

    def mark_target_visited(self, target: str):
        with self._lock:
            self._conn.execute(
                "UPDATE targets SET visited=1, last_seen=? WHERE target=?",
                (self._now(), target)
            )
            self._conn.commit()

    def add_endpoint(self, scan_id: str, target: str, url: str, kind: str = 'url', score: float = 0.0):
        with self._lock:
            ts = self._now()
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO endpoints(scan_id, target, url, kind, score, first_seen, last_seen, visited) VALUES(?,?,?,?,?,?,?,0)",
                    (scan_id, target, url, kind, float(score), ts, ts)
                )
                self._conn.execute(
                    "UPDATE endpoints SET last_seen=?, score=MAX(score, ?) WHERE url=?",
                    (ts, float(score), url)
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def mark_endpoint_visited(self, url: str):
        with self._lock:
            self._conn.execute(
                "UPDATE endpoints SET visited=1, last_seen=? WHERE url=?",
                (self._now(), url)
            )
            self._conn.commit()

    def add_parameter(self, endpoint_url: str, name: str):
        with self._lock:
            ts = self._now()
            cur = self._conn.execute("SELECT id FROM endpoints WHERE url=?", (endpoint_url,))
            row = cur.fetchone()
            if not row:
                return
            eid = row['id']
            self._conn.execute(
                "INSERT OR IGNORE INTO parameters(endpoint_id, name, first_seen) VALUES(?,?,?)",
                (eid, name, ts)
            )
            self._conn.commit()

    def add_tech(self, scan_id: str, target: str, name: str, version: Optional[str] = None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO tech(scan_id, target, name, version, first_seen) VALUES(?,?,?,?,?)",
                (scan_id, target, name, version or '', self._now())
            )
            self._conn.commit()

    # Findings and artifacts
    @staticmethod
    def _finding_hash(scan_id: str, target: str, url: str, ftype: str, evidence: str) -> str:
        h = hashlib.sha256()
        h.update((scan_id or '').encode())
        h.update((target or '').encode())
        h.update((url or '').encode())
        h.update((ftype or '').encode())
        h.update((evidence or '').encode())
        return h.hexdigest()

    def add_finding(self, scan_id: str, target: str, url: str, ftype: str, severity: str, evidence: str, module: str) -> bool:
        """Insert a finding if not duplicate; return True if inserted."""
        with self._lock:
            fhash = self._finding_hash(scan_id, target, url, ftype, evidence)
            try:
                self._conn.execute(
                    "INSERT OR IGNORE INTO findings(scan_id, target, url, type, severity, evidence, module, timestamp, hash) VALUES(?,?,?,?,?,?,?,?,?)",
                    (scan_id, target, url, ftype, severity, evidence, module, self._now(), fhash)
                )
                self._conn.commit()
                cur = self._conn.execute("SELECT changes() AS c")
                return bool(cur.fetchone()['c'])
            except Exception:
                self._conn.rollback()
                return False

    def add_artifact(self, scan_id: str, kind: str, path: str, metadata: Optional[Dict[str, Any]] = None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO artifacts(scan_id, kind, path, metadata_json, created_at) VALUES(?,?,?,?,?)",
                (scan_id, kind, path, json.dumps(metadata or {}), self._now())
            )
            self._conn.commit()

    # Actions and signatures (for de-dup and audit)
    def record_action(self, scan_id: str, action: str, module: str, target: str, url: str, payload: Optional[str], success: bool, details: str = ""):
        with self._lock:
            self._conn.execute(
                "INSERT INTO actions(scan_id, ts, action, module, target, url, payload, success, details) VALUES(?,?,?,?,?,?,?,?,?)",
                (scan_id, self._now(), action, module, target, url, payload or '', 1 if success else 0, details)
            )
            self._conn.commit()

    @staticmethod
    def make_signature(url: str, param: Optional[str] = None, payload: Optional[str] = None) -> str:
        h = hashlib.sha256()
        h.update((url or '').encode())
        h.update((param or '').encode())
        h.update((payload or '').encode())
        return h.hexdigest()

    def signature_seen(self, scan_id: str, signature: str) -> bool:
        with self._lock:
            cur = self._conn.execute("SELECT 1 FROM signatures WHERE signature=?", (signature,))
            return cur.fetchone() is not None

    def remember_signature(self, scan_id: str, signature: str):
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO signatures(scan_id, signature, first_seen) VALUES(?,?,?)",
                (scan_id, signature, self._now())
            )
            self._conn.commit()

    # Prioritization
    @staticmethod
    def _score_endpoint(url: str, kind: str = 'url') -> float:
        """Heuristic scoring for endpoint priority."""
        score = 0.0
        u = url.lower()
        # API endpoints
        if '/api/' in u or u.endswith('/api'):
            score += 2.5
        # GraphQL
        if '/graphql' in u:
            score += 2.0
        # Auth/admin
        if any(k in u for k in ['/admin', '/signin', '/login', '/auth', '/dashboard']):
            score += 2.0
        # Parameterized
        if '?' in u:
            score += 1.5
        # Sensitive names
        if any(k in u for k in ['token', 'secret', 'key', 'redirect', 'file=', 'path=']):
            score += 1.5
        # Depth bonus up to a point
        depth = u.count('/')
        score += min(depth * 0.05, 0.5)
        # Kinds
        if kind and kind != 'url':
            score += 0.2
        return score

    def queue_endpoint(self, scan_id: str, target: str, url: str, kind: str = 'url'):
        score = self._score_endpoint(url, kind)
        self.add_endpoint(scan_id, target, url, kind, score)

    def next_endpoints(self, limit: int = 10) -> List[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT url FROM endpoints WHERE visited=0 ORDER BY score DESC, last_seen DESC LIMIT ?",
                (limit,)
            )
            return [r['url'] for r in cur.fetchall()]

    def all_findings(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if scan_id:
                cur = self._conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY timestamp DESC", (scan_id,))
            else:
                cur = self._conn.execute("SELECT * FROM findings ORDER BY timestamp DESC")
            return [dict(r) for r in cur.fetchall()]

    def get_scan_stats(self, scan_id: str) -> Dict[str, Any]:
        with self._lock:
            stats: Dict[str, Any] = {}
            cur = self._conn.execute("SELECT COUNT(*) AS c FROM endpoints WHERE scan_id=?", (scan_id,))
            stats['endpoints'] = cur.fetchone()['c']
            cur = self._conn.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id=?", (scan_id,))
            stats['findings'] = cur.fetchone()['c']
            cur = self._conn.execute("SELECT COUNT(*) AS c FROM actions WHERE scan_id=?", (scan_id,))
            stats['actions'] = cur.fetchone()['c']
            return stats

# Optional convenience API for Engine
class AgentContext:
    """A light wrapper combining MemoryStore with convenience methods for the agent."""
    def __init__(self, memory: MemoryStore, scan_id: str, target: str, config: Optional[Dict[str, Any]] = None):
        self.mem = memory
        self.scan_id = scan_id
        self.target = target
        self.mem.new_scan(scan_id, target, config or {})

    def add_discovered_urls(self, urls: List[str], kind: str = 'url'):
        for u in urls or []:
            try:
                self.mem.queue_endpoint(self.scan_id, self.target, u, kind)
            except Exception:
                continue

    def record_finding(self, finding: Dict[str, Any], module: str):
        self.mem.add_finding(
            scan_id=self.scan_id,
            target=finding.get('target', self.target),
            url=finding.get('url', ''),
            ftype=finding.get('type', 'Unknown'),
            severity=finding.get('severity', 'Info'),
            evidence=finding.get('evidence', ''),
            module=module,
        )

    def select_next(self, limit: int = 10) -> List[str]:
        return self.mem.next_endpoints(limit)

    def visited(self, url: str):
        self.mem.mark_endpoint_visited(url)

    def action(self, module: str, url: str, payload: Optional[str], success: bool, details: str = ""):
        self.mem.record_action(self.scan_id, 'execute', module, self.target, url, payload, success, details)

    def finalize(self):
        self.mem.end_scan(self.scan_id)
