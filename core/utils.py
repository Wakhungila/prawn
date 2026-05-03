#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN Utilities

This module provides utility functions used across the PRAWN framework.
"""

import os
import re
import json
import random
import string
import logging
import subprocess
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger('PRAWN.Utils')

# PRAWN Spinner Verbs - High-fidelity "thought" verbs for CLI status updates
SPINNER_VERBS = [
    "COBOMBULATING", "EXFILTRATING", "OSSIFYING", "DECIMATING", "DISSECTING", "PROBING",
    "INFILTRATING", "SCOURING", "SATURATING", "HARVESTING", "CORRALING", "RAKING",
    "TREPANNING", "EXCAVATING", "FORAGING", "SIFTING", "CULLING", "SNARING",
    "GELATING", "ANCHORING", "ENMESHING", "SURVEYING", "SHADOWING", "SPLICING",
    "FRACTURING", "DREDGING", "GLOMMING", "RIVETING", "SCOOPING", "SKEWERING",
    "SPIKING", "TRACING", "TRIANGULATING", "UNEARTHING", "UNPACKING", "WINNOWING",
    "WRENCHING", "YANKING", "ZIPPERING", "BIFURCATING", "LACERATING", "DISLOCATING",
    "INCINERATING", "STRANGULATING", "CORRODING", "VULNERATING", "OVERRIDING",
    "PULVERIZING", "EVISCERATING", "GRINDING", "HAMMERING", "PIERCING", "RAMMING",
    "SHATTERING", "SMASHING", "THRASHING", "UPROOTING", "CRUSHING", "DENTING",
    "DRILLING", "FLAYING", "GOUGING", "HEWING", "JOLTING", "MAIMING", "QUASHING",
    "RENDING", "SCARRING", "SLICING", "SPLINTERING", "SUNDERING", "TANKING",
    "TEARING", "THUMPING", "TRASHING", "VAMPING", "WARPING", "WRACKING", "TRANSMUTING",
    "DISSOLVING", "FORGING", "TEMPERING", "CRYSTALLIZING", "ANNEALING", "SMELTING",
    "WELDING", "CAUTERIZING", "FUSING", "ATOMIZING", "VAPORIZING"
]

# Manual mode proxy + HTTP log (for HAR/PoC export)
_MANUAL_PROXY_ENABLED = False
_MANUAL_PROXY_ADDR = None  # e.g., 'http://127.0.0.1:8080'
_HTTP_LOG = []  # list of {ts, request: {...}, response: {...}}

def set_manual_proxy(enabled: bool, addr: str = None):
    global _MANUAL_PROXY_ENABLED, _MANUAL_PROXY_ADDR
    _MANUAL_PROXY_ENABLED = bool(enabled)
    if addr:
        _MANUAL_PROXY_ADDR = addr
    logger.info(f"Manual proxy set: enabled={_MANUAL_PROXY_ENABLED}, addr={_MANUAL_PROXY_ADDR}")

def get_manual_proxy():
    return {'enabled': _MANUAL_PROXY_ENABLED, 'addr': _MANUAL_PROXY_ADDR}

def _append_http_log(entry: dict):
    try:
        entry['ts'] = datetime.utcnow().isoformat() + 'Z'
        _HTTP_LOG.append(entry)
        # bound log size
        if len(_HTTP_LOG) > 5000:
            del _HTTP_LOG[: len(_HTTP_LOG) - 5000]
    except Exception:
        pass

def get_http_log(limit: int = 500) -> list:
    if limit and limit > 0:
        return _HTTP_LOG[-limit:]
    return list(_HTTP_LOG)

def clear_http_log():
    _HTTP_LOG.clear()

def export_har(entries: list = None) -> dict:
    """Export a minimal HAR dictionary from logged entries."""
    items = entries if entries is not None else get_http_log()
    har_entries = []
    for e in items:
        req = e.get('request', {})
        resp = e.get('response', {})
        har_entries.append({
            'startedDateTime': e.get('ts') or datetime.utcnow().isoformat() + 'Z',
            'time': resp.get('time_ms', 0),
            'request': {
                'method': req.get('method', 'GET'),
                'url': req.get('url', ''),
                'httpVersion': 'HTTP/1.1',
                'headers': [{'name': k, 'value': v} for k, v in (req.get('headers') or {}).items()],
                'queryString': [],
                'cookies': [],
                'headersSize': -1,
                'bodySize': len((req.get('data') or '')) if isinstance(req.get('data'), str) else -1,
                'postData': {'mimeType': 'application/x-www-form-urlencoded', 'text': req.get('data') or ''} if req.get('data') else None,
            },
            'response': {
                'status': resp.get('status', 0),
                'statusText': '',
                'httpVersion': 'HTTP/1.1',
                'headers': [{'name': k, 'value': v} for k, v in (resp.get('headers') or {}).items()],
                'cookies': [],
                'content': {'size': len(resp.get('text') or ''), 'mimeType': resp.get('headers', {}).get('content-type', ''), 'text': resp.get('text') or ''},
                'redirectURL': '',
                'headersSize': -1,
                'bodySize': len(resp.get('text') or ''),
            },
            'cache': {},
            'timings': {'send': 0, 'wait': resp.get('time_ms', 0), 'receive': 0},
            'serverIPAddress': '',
            'connection': ''
        })
    return {'log': {'version': '1.2', 'creator': {'name': 'PRAWN', 'version': '0.1'}, 'entries': har_entries}}

def generate_curl_from_entry(entry: dict) -> str:
    req = entry.get('request', {})
    method = req.get('method', 'GET')
    url = req.get('url', '')
    headers = req.get('headers') or {}
    data = req.get('data')
    parts = ['curl', '-i', '-sS', '-k', '-X', method]
    for k, v in headers.items():
        parts += ['-H', f"{k}: {v}"]
    if data:
        parts += ['--data', data]
    parts.append(url)
    return ' '.join(parts)

# User agent list for randomization
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
]

def get_random_user_agent():
    """Get a random user agent string."""
    return random.choice(USER_AGENTS)

def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def is_valid_url(url):
    """Check if a URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_valid_ip(ip):
    """Check if a string is a valid IPv4 address."""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None

def run_command(command, timeout=60):
    """Run a shell command and return the output."""
    try:
        logger.debug(f"Running command: {command}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return {
            'success': process.returncode == 0,
            'returncode': process.returncode,
            'stdout': stdout,
            'stderr': stderr
        }
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout} seconds: {command}")
        return {
            'success': False,
            'returncode': -1,
            'stdout': '',
            'stderr': f'Command timed out after {timeout} seconds'
        }
    except Exception as e:
        logger.error(f"Error running command: {e}")
        return {
            'success': False,
            'returncode': -1,
            'stdout': '',
            'stderr': str(e)
        }

def make_request(url, method='GET', headers=None, data=None, params=None, timeout=30, verify=True, allow_redirects=True, proxies=None):
    """Make an HTTP request and return the response. Honors Manual Mode proxy and logs request/response for export."""
    if headers is None:
        headers = {'User-Agent': get_random_user_agent()}
    
    eff_proxies = proxies
    if eff_proxies is None and _MANUAL_PROXY_ENABLED and _MANUAL_PROXY_ADDR:
        eff_proxies = {'http': _MANUAL_PROXY_ADDR, 'https': _MANUAL_PROXY_ADDR}
    
    req_record = {'method': method, 'url': url, 'headers': dict(headers or {}), 'data': data if isinstance(data, str) else (json.dumps(data) if isinstance(data, dict) else None)}
    try:
        import requests
        t0 = datetime.utcnow()
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=params,
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            proxies=eff_proxies
        )
        dt_ms = int((datetime.utcnow() - t0).total_seconds() * 1000)
        resp_record = {
            'status': response.status_code,
            'headers': dict(response.headers),
            'text': response.text,
            'time_ms': dt_ms
        }
        _append_http_log({'request': req_record, 'response': resp_record})
        return {
            'success': True,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.content,
            'text': response.text,
            'url': response.url
        }
    except Exception as e:
        logger.error(f"Request error: {e}")
        _append_http_log({'request': req_record, 'response': {'status': 0, 'headers': {}, 'text': str(e), 'time_ms': 0}})
        return {
            'success': False,
            'error': str(e)
        }

def save_json(data, filename):
    """Save data as JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving JSON: {e}")
        return False

def load_json(filename):
    """Load data from JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading JSON: {e}")
        return None

def ensure_directory(directory):
    """Ensure directory exists, create if it doesn't."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory

# Compatibility aliases
# Some modules expect legacy helper names.

def ensure_dir_exists(directory):
    """Alias for ensure_directory."""
    return ensure_directory(directory)

def save_json_output(data, filename):
    """Alias for save_json."""
    return save_json(data, filename)

def make_http_request(*args, **kwargs):
    """Alias for make_request for compatibility with some modules."""
    return make_request(*args, **kwargs)

def normalize_url(url):
    """Normalize URL by ensuring it has a scheme and removing trailing slash."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url.rstrip('/')

def calculate_severity(cvss_score):
    """Calculate severity based on CVSS score."""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score >= 0.1:
        return "Low"
    else:
        return "None"