#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GraphQL Scanner Module for PRAWN

Performs safe checks against GraphQL endpoints:
- Endpoint discovery (common paths)
- Introspection enabled (production misconfiguration)
- Depth/complexity heuristics (simple nested schema queries)
- Alias batching heuristic

Notes:
- This module avoids destructive mutations and focuses on read-only queries.
- Results are returned as standardized vulnerabilities with evidence snippets.
"""

import os
import time
import json
import logging
import urllib.parse as urlparse
from typing import List, Dict

from core.base_module import VulnTestingModule
from core.utils import make_request, ensure_dir_exists, save_json

logger = logging.getLogger('prawn.vuln_testing.graphql_scanner')

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { name }
        directives { name }
      }
    }
    """
}

# A moderately heavy nested query that should be safe but exercise depth
# by walking the schema types and fields.
NESTED_SCHEMA_QUERY = {
    "query": """
    query SchemaDepthProbe {
      __schema {
        types {
          name
          fields(includeDeprecated: true) {
            name
            type { name ofType { name ofType { name } } }
          }
        }
      }
    }
    """
}

# Many alias queries of __typename to probe batching/alias handling safely.
ALIAS_BATCH_QUERY = {
    "query": """
    query AliasBatch {
      a1: __typename
      a2: __typename
      a3: __typename
      a4: __typename
      a5: __typename
      a6: __typename
      a7: __typename
      a8: __typename
      a9: __typename
      a10: __typename
      a11: __typename
      a12: __typename
      a13: __typename
      a14: __typename
      a15: __typename
      a16: __typename
      a17: __typename
      a18: __typename
      a19: __typename
      a20: __typename
    }
    """
}

# A deeply nested query to test for depth limit bypass.
DEPTH_BYPASS_QUERY = {
    "query": """
    query DepthLimitBypass {
      __schema {
        types {
          possibleTypes {
            possibleTypes {
              possibleTypes {
                possibleTypes {
                  name
                }
              }
            }
          }
        }
      }
    }
    """
}

class GraphQLScanner(VulnTestingModule):
    def __init__(self):
        super().__init__()
        self.name = 'graphql_scanner'
        self.description = 'Detects GraphQL endpoints and common misconfigurations'
        self.category = 'vuln_testing'
        self.author = 'PRAWN'
        self.version = '0.1.0'
        self.vulnerabilities: List[Dict] = []

    def run(self, target: str, config: Dict = None):
        logger.info(f"Starting GraphQL scanning on {target}")
        if not target:
            return {'vulnerabilities': []}
        if config is None:
            config = {}
        target = self._normalize_target(target)

        # Discover candidate endpoints
        candidates = self._candidate_endpoints(target)
        headers = {'Content-Type': 'application/json'}

        for ep in candidates:
            # Probe simple POST and record basic detection
            det = make_request(ep, method='POST', headers=headers, data=json.dumps({"query": "{ __typename }"}), timeout=20)
            if not det.get('success'):
                continue
            status = det.get('status_code', 0)
            if status in (200, 400, 415):
                self._report_info('GraphQL Endpoint Detected', ep, evidence=f"HTTP {status}")

                # Introspection check
                self._check_introspection(ep, headers)
                # Depth/complexity heuristic
                self._check_depth_complexity(ep, headers)
                # Alias batching heuristic
                self._check_alias_batching(ep, headers)
                # Depth limit bypass check
                self._check_depth_limit_bypass(ep, headers)

        # Save results (optional)
        out_dir = ensure_dir_exists(os.path.join('results', 'vuln_testing'))
        out_file = os.path.join(out_dir, f"graphql_scan_{int(time.time())}.json")
        try:
            save_json({'target': target, 'vulnerabilities': self.vulnerabilities}, out_file)
        except Exception:
            pass

        logger.info(f"GraphQL scanning complete on {target}. Findings: {len(self.vulnerabilities)}")
        return {'vulnerabilities': self.vulnerabilities, 'results_file': out_file}

    # --- checks -------------------------------------------------------------

    def _check_introspection(self, endpoint: str, headers: Dict):
        t0 = time.time()
        resp = make_request(endpoint, method='POST', headers=headers, data=json.dumps(INTROSPECTION_QUERY), timeout=30)
        dt = time.time() - t0
        if not resp.get('success'):
            return
        text = resp.get('text') or ''
        try:
            jr = json.loads(text)
        except Exception:
            jr = {}
            
        if isinstance(jr, dict) and 'data' in jr and isinstance(jr['data'], dict) and '__schema' in jr['data']:
            self._report('GraphQL Introspection Enabled', 'High', endpoint, evidence='__schema present in response', payload='IntrospectionQuery', remediation='Disable introspection in production or restrict by role')
            # Trigger dynamic auth bypass check using the discovered schema
            self._check_dynamic_field_auth_bypass(endpoint, headers, jr['data']['__schema'])
        elif 'errors' in jr:
            # If errors mention introspection disabled, note as info
            errs = json.dumps(jr.get('errors'))[:300]
            if 'introspection' in errs.lower():
                self._report_info('GraphQL Introspection Restricted', endpoint, evidence=errs)

    def _check_depth_complexity(self, endpoint: str, headers: Dict):
        # Compare baseline vs nested schema query latency
        base = make_request(endpoint, method='POST', headers=headers, data=json.dumps({"query": "{ __typename }"}), timeout=20)
        if not base.get('success'):
            return
        t0 = time.time()
        heavy = make_request(endpoint, method='POST', headers=headers, data=json.dumps(NESTED_SCHEMA_QUERY), timeout=60)
        dt = time.time() - t0
        if heavy.get('success'):
            # If the server returns 200 with large body and high latency, hint at missing depth/complexity controls
            body_len = len(heavy.get('text') or '')
            if dt > 5 or body_len > 200000:
                self._report('GraphQL Depth/Complexity Controls Missing (Heuristic)', 'Medium', endpoint, evidence=f'Latency {dt:.2f}s, size {body_len} bytes', payload='Nested schema query', remediation='Enforce query depth/complexity limits or cost analysis')

    def _check_depth_limit_bypass(self, endpoint: str, headers: Dict):
        """Tests if the server processes a deeply nested query that should typically be blocked."""
        resp = make_request(endpoint, method='POST', headers=headers, data=json.dumps(DEPTH_BYPASS_QUERY), timeout=40)
        if not resp.get('success'):
            return
        
        # If the server processes a query this deep with a 200 OK, it's likely vulnerable to DoS via depth exhaustion
        if resp.get('status_code') == 200 and "data" in (resp.get('text') or ""):
            self._report('GraphQL Query Depth Limit Bypass', 'High', endpoint, evidence='Deeply nested query accepted', payload='DEPTH_BYPASS_QUERY', remediation='Implement strict query depth limiting in the GraphQL middleware')

    def _check_dynamic_field_auth_bypass(self, endpoint: str, headers: Dict, schema: Dict):
        """
        Analyzes the discovered schema to find sensitive types and builds a dynamic probe.
        """
        types = schema.get('types', [])
        sensitive_keywords = ['user', 'admin', 'vault', 'secret', 'key', 'auth', 'profile', 'email', 'phone', 'role', 'token']
        
        # Find types that look sensitive
        interesting_types = [t for t in types if any(k in t.get('name', '').lower() for k in sensitive_keywords) and t.get('kind') == 'OBJECT']
        
        if not interesting_types:
            return

        # Build a query targeting the first few fields of the first few sensitive objects
        query_parts = []
        for t in interesting_types[:3]:
            type_name = t['name']
            # In a real scenario, we'd need to find the Query root field that returns this type.
            # Here we use a common heuristic: lowercase type name
            field_name = type_name[0].lower() + type_name[1:]
            query_parts.append(f"  {field_name} {{ __typename }}")

        dynamic_query = {"query": f"query DynamicAuthProbe {{\n{os.linesep.join(query_parts)}\n}}"}
        
        resp = make_request(endpoint, method='POST', headers=headers, data=json.dumps(dynamic_query), timeout=30)
        if not resp.get('success'):
            return

        try:
            jr = json.loads(resp.get('text') or '{}')
            data = jr.get('data', {})
            if data and any(v is not None for v in data.values()):
                self._report('GraphQL Field-Level Authorization Bypass', 'Critical', endpoint, 
                             evidence=f"Discovered types {list(data.keys())} returned data without auth", 
                             payload=dynamic_query['query'], 
                             remediation='Ensure all sensitive object resolvers implement authorization checks.')
        except Exception:
            pass

    def _check_alias_batching(self, endpoint: str, headers: Dict):
        # Heuristic: send many aliases and note if server handles as heavy uncontrolled batch
        t0 = time.time()
        resp = make_request(endpoint, method='POST', headers=headers, data=json.dumps(ALIAS_BATCH_QUERY), timeout=30)
        dt = time.time() - t0
        if resp.get('success') and resp.get('status_code') == 200 and dt > 3:
            self._report('GraphQL Alias Batching Unrestricted (Heuristic)', 'Low', endpoint, evidence=f'Latency {dt:.2f}s for alias batch', payload='Alias batch query', remediation='Implement rate limiting and query cost limits; restrict batching/aliases')

    # --- helpers ------------------------------------------------------------

    def _normalize_target(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def _candidate_endpoints(self, url: str) -> List[str]:
        p = urlparse.urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        paths = [
            '/graphql',
            '/api/graphql',
            '/v1/graphql',
            f"{p.path.rstrip('/')}/graphql" if p.path else '/graphql',
        ]
        seen = set()
        out = []
        for path in paths:
            full = path if path.startswith('http') else (base + path)
            if full not in seen:
                seen.add(full)
                out.append(full)
        return out

    def _report(self, vtype: str, severity: str, url: str, evidence: str = None, payload: str = None, remediation: str = None):
        item = {
            'type': vtype,
            'severity': severity,
            'url': url,
            'parameter': None,
            'payload': payload,
            'evidence': evidence,
            'remediation': remediation,
            'timestamp': int(time.time())
        }
        self.vulnerabilities.append(item)
        logger.info(f"[GraphQL] {severity} {vtype} at {url}")

    def _report_info(self, vtype: str, url: str, evidence: str = None):
        self._report(vtype, 'Info', url, evidence=evidence)
