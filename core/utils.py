#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Utilities

This module provides utility functions used across the PIN0CCHI0 framework.
"""

import os
import re
import json
import random
import string
import logging
import subprocess
from urllib.parse import urlparse

logger = logging.getLogger('PIN0CCHI0.Utils')

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
    """Make an HTTP request and return the response."""
    if headers is None:
        headers = {'User-Agent': get_random_user_agent()}
    
    try:
        # Lazy import to avoid hard dependency during test discovery
        import requests
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            params=params,
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            proxies=proxies
        )
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