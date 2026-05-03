#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Access Control Scanner Module for PIN0CCHI0

This module tests for access control vulnerabilities including:
- Broken access controls
- Insecure direct object references (IDOR)
- Missing function level access controls
- Privilege escalation
- Horizontal and vertical access control issues

Author: PIN0CCHI0 Team
Version: 1.0
"""

import re
import json
import logging
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.utils import make_request, save_json_output

# Configure logger # type: ignore
logger = logging.getLogger('pin0cchi0.vuln_testing.access_control_scanner')

class AccessControlScanner(BaseModule):
    """
    Scanner for detecting access control vulnerabilities in web applications.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Access Control Scanner"
        self.description = "Tests for access control vulnerabilities in web applications"
        self.category = "Vulnerability Testing"
        self.vulnerabilities = []
        self.user_roles = []
        self.protected_endpoints = []
        self.callback_domain = None
        self.logger = logger # Initialize logger for the instance
        self.results_dir = None
        
    def run(self, target, config=None):
        """
        Run the access control scanner against the target.
        
        Args:
            target (str): The target URL or domain
            config (dict): Configuration options
        
        Returns:
            dict: Results of the scan
        """
        logger.info(f"Starting access control scan on {target}")
        
        self.target = target
        self.config = config or {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = self.config.get('output_dir', './results')
        
        # Discover user roles if provided in config
        self.user_roles = self.config.get('user_roles', [])
        
        # If no user roles provided, use default roles
        if not self.user_roles:
            self.user_roles = [
                {'name': 'anonymous', 'credentials': None},
                {'name': 'user', 'credentials': {'username': 'user', 'password': 'password'}},
                {'name': 'admin', 'credentials': {'username': 'admin', 'password': 'admin'}}
            ]
        
        # Discover protected endpoints
        self._discover_protected_endpoints()
        
        # Test for horizontal access control issues
        self._test_horizontal_access_control()
        
        # Test for vertical access control issues
        self._test_vertical_access_control()
        
        # Test for missing function level access controls
        self._test_function_level_access_control()
        
        # Test for forced browsing vulnerabilities
        self._test_forced_browsing()
        
        # Test for API access control issues
        self._test_api_access_control()
        
        # Consolidate results
        results = self._consolidate_results()
        
        # Save results
        output_file = f"{self.results_dir}/access_control_scan_{timestamp}.json"
        save_json_output(output_file, results)
        
        logger.info(f"Access control scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        
        return results
    
    def _discover_protected_endpoints(self):
        """
        Discover protected endpoints in the application.
        """
        logger.info("Discovering protected endpoints")
        
        # Check common admin paths
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/administrator/',
            '/wp-admin', '/wp-admin/', '/dashboard', '/dashboard/',
            '/manage', '/manage/', '/management', '/management/',
            '/control', '/control/', '/panel', '/panel/',
            '/console', '/console/', '/cp', '/cp/',
            '/backend', '/backend/', '/admin-panel', '/admin-panel/',
            '/adm', '/adm/', '/siteadmin', '/siteadmin/',
            '/moderator', '/moderator/', '/webadmin', '/webadmin/',
            '/adminarea', '/adminarea/', '/bb-admin', '/bb-admin/',
            '/adminLogin', '/adminLogin/', '/admin_area', '/admin_area/',
            '/panel-administracion', '/panel-administracion/',
            '/instadmin', '/instadmin/', '/memberadmin', '/memberadmin/',
            '/administratorlogin', '/administratorlogin/', '/adm/index.php', '/admin/index.php'
        ]
        
        # Check each admin path
        for path in admin_paths:
            url = urllib.parse.urljoin(self.target, path)
            response = make_request(url)
            
            if response.get('success'):
                status_code = response['status_code']
                
                # If we get a 401, 403, or a login page, it's likely protected
                if status_code in [401, 403] or self._is_login_page(response['text']):
                    self.protected_endpoints.append({
                        'url': url,
                        'status_code': status_code,
                        'requires_auth': True
                    })
                    logger.info(f"Found protected endpoint: {url} (Status: {status_code})")
        
        # Also check for API endpoints that might be protected
        api_paths = [
            '/api/users', '/api/v1/users', '/api/v2/users',
            '/api/admin', '/api/v1/admin', '/api/v2/admin',
            '/api/settings', '/api/v1/settings', '/api/v2/settings',
            '/api/config', '/api/v1/config', '/api/v2/config'
        ]
        
        for path in api_paths:
            url = urllib.parse.urljoin(self.target, path)
            response = make_request(url)
            
            if response.get('success'):
                status_code = response['status_code']
                
                # If we get a 401 or 403, it's likely protected
                if status_code in [401, 403]:
                    self.protected_endpoints.append({
                        'url': url,
                        'status_code': status_code,
                        'requires_auth': True,
                        'is_api': True
                    })
                    logger.info(f"Found protected API endpoint: {url} (Status: {status_code})")
    
    def _is_login_page(self, html_content):
        """
        Check if the page is a login page.
        
        Args:
            html_content (str): HTML content of the page
            
        Returns:
            bool: True if it's a login page, False otherwise
        """
        # Look for common login page indicators
        login_indicators = [
            r'<form[^>]*login[^>]*>',
            r'<input[^>]*password[^>]*>',
            r'<input[^>]*username[^>]*>',
            r'<input[^>]*email[^>]*>.*<input[^>]*password[^>]*>',
            r'login',
            r'sign in',
            r'signin',
            r'log in',
            r'username',
            r'password',
            r'forgot password',
            r'reset password',
            r'remember me'
        ]
        
        html_lower = html_content.lower()
        
        for indicator in login_indicators:
            if re.search(indicator, html_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _test_horizontal_access_control(self):
        """
        Test for horizontal access control issues (accessing other users' data).
        """
        logger.info("Testing for horizontal access control issues")
        
        # Common patterns for user-specific resources
        resource_patterns = [
            '/users/{id}',
            '/user/{id}',
            '/profiles/{id}',
            '/profile/{id}',
            '/accounts/{id}',
            '/account/{id}',
            '/members/{id}',
            '/member/{id}',
            '/customers/{id}',
            '/customer/{id}'
        ]
        
        # Test IDs to try
        test_ids = ['1', '2', '3', '4', '5', '10', '100']
        
        # For each user role that has credentials
        for role in self.user_roles:
            if not role['credentials']:
                continue
                
            # Get authenticated session for this role
            session_cookies = self._authenticate(role['credentials'])
            
            if not session_cookies:
                logger.warning(f"Failed to authenticate as {role['name']}")
                continue
                
            logger.info(f"Authenticated as {role['name']}")
            
            # Test each resource pattern with different IDs
            for pattern in resource_patterns:
                for test_id in test_ids:
                    url = urllib.parse.urljoin(self.target, pattern.replace('{id}', test_id))
                    
                    # Make request with session cookies
                    response = make_request(url, cookies=session_cookies)
                    
                    if response.get('success') and response.get('status_code') == 200:
                        # Check if the response contains sensitive data
                        if self._contains_sensitive_data(response['text']):
                            vulnerability = {
                                'url': url,
                                'type': 'Horizontal Access Control',
                                'role': role['name'],
                                'description': f"User with role {role['name']} can access resource with ID {test_id}",
                                'severity': 'High',
                                'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                            }
                            
                            self.vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential horizontal access control issue found at {url} for role {role['name']}")
    
    def _test_vertical_access_control(self):
        """
        Test for vertical access control issues (privilege escalation).
        """
        logger.info("Testing for vertical access control issues")
        
        # Common admin/privileged endpoints
        privileged_endpoints = [
            '/admin/users',
            '/admin/settings',
            '/admin/config',
            '/admin/dashboard',
            '/settings',
            '/configuration',
            '/users/manage',
            '/api/admin/users',
            '/api/v1/admin/users',
            '/api/v2/admin/users'
        ]
        
        # For each user role
        for role in self.user_roles:
            # Skip the highest privilege role (assumed to be the last one)
            if role == self.user_roles[-1]:
                continue
                
            # Get authenticated session for this role
            session_cookies = None
            if role['credentials']:
                session_cookies = self._authenticate(role['credentials'])
            
            # Test each privileged endpoint
            for endpoint in privileged_endpoints:
                url = urllib.parse.urljoin(self.target, endpoint)
                
                # Make request with session cookies if available
                response = make_request(url, cookies=session_cookies)
                
                if response.get('success') and response.get('status_code') == 200:
                    # Check if the response contains admin features
                    if self._contains_admin_features(response['text']):
                        vulnerability = {
                            'url': url,
                            'type': 'Vertical Access Control',
                            'role': role['name'],
                            'description': f"User with role {role['name']} can access admin endpoint {endpoint}",
                            'severity': 'Critical',
                            'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                        }
                        
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Potential vertical access control issue found at {url} for role {role['name']}")
    
    def _test_function_level_access_control(self):
        """
        Test for missing function level access controls.
        """
        logger.info("Testing for missing function level access controls")
        
        # Common function endpoints that should be protected
        function_endpoints = [
            '/api/deleteUser',
            '/api/v1/deleteUser',
            '/api/v2/deleteUser',
            '/api/updateUser',
            '/api/v1/updateUser',
            '/api/v2/updateUser',
            '/api/addUser',
            '/api/v1/addUser',
            '/api/v2/addUser',
            '/api/deleteItem',
            '/api/v1/deleteItem',
            '/api/v2/deleteItem',
            '/api/updateItem',
            '/api/v1/updateItem',
            '/api/v2/updateItem',
            '/api/addItem',
            '/api/v1/addItem',
            '/api/v2/addItem'
        ]
        
        # For each user role
        for role in self.user_roles:
            # Get authenticated session for this role
            session_cookies = None
            if role['credentials']:
                session_cookies = self._authenticate(role['credentials'])
            
            # Test each function endpoint
            for endpoint in function_endpoints:
                url = urllib.parse.urljoin(self.target, endpoint)
                
                # Try both GET and POST requests
                for method in ['GET', 'POST']:
                    # For POST, include a simple JSON payload
                    data = None
                    if method == 'POST':
                        data = {'id': 1}
                    
                    # Make request with session cookies if available
                    response = make_request(url, method=method, json_data=data, cookies=session_cookies)

                    if response.get('success') and response.get('status_code', 0) < 400:
                        vulnerability = {
                            'url': url,
                            'type': 'Missing Function Level Access Control',
                            'role': role['name'],
                            'method': method,
                            'description': f"User with role {role['name']} can access function endpoint {endpoint} with {method}",
                            'severity': 'High',
                            'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                        }
                        
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Potential missing function level access control found at {url} with {method} for role {role['name']}")
    
    def _test_forced_browsing(self):
        """
        Test for forced browsing vulnerabilities.
        """
        logger.info("Testing for forced browsing vulnerabilities")
        
        # Common hidden or protected pages
        hidden_pages = [
            '/backup',
            '/backup.zip',
            '/backup.tar.gz',
            '/db',
            '/database',
            '/database.sql',
            '/db.sql',
            '/config',
            '/config.php',
            '/config.js',
            '/config.json',
            '/settings.json',
            '/settings.php',
            '/settings.js',
            '/admin.php',
            '/admin.html',
            '/administrator.php',
            '/administrator.html',
            '/secret',
            '/private',
            '/dev',
            '/development',
            '/staging',
            '/test',
            '/phpinfo.php',
            '/info.php',
            '/.git',
            '/.git/config',
            '/.svn',
            '/.svn/entries',
            '/.env',
            '/web.config',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        # Test each hidden page
        for page in hidden_pages:
            url = urllib.parse.urljoin(self.target, page)
            response = make_request(url)

            if response.get('success') and response.get('status_code') == 200:
                vulnerability = {
                    'url': url,
                    'type': 'Forced Browsing',
                    'description': f"Hidden or protected page {page} is accessible",
                    'severity': 'Medium',
                    'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                }
                
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Potential forced browsing vulnerability found at {url}")
    
    def _test_api_access_control(self):
        """
        Test for API access control issues.
        """
        logger.info("Testing for API access control issues")
        
        # Common API endpoints that should be protected
        api_endpoints = [
            '/api/users',
            '/api/v1/users',
            '/api/v2/users',
            '/api/user/1',
            '/api/v1/user/1',
            '/api/v2/user/1',
            '/api/admin',
            '/api/v1/admin',
            '/api/v2/admin',
            '/api/settings',
            '/api/v1/settings',
            '/api/v2/settings',
            '/api/config',
            '/api/v1/config',
            '/api/v2/config',
            '/api/internal',
            '/api/v1/internal',
            '/api/v2/internal'
        ]
        
        # For each user role
        for role in self.user_roles:
            # Get authenticated session for this role
            session_cookies = None
            if role['credentials']:
                session_cookies = self._authenticate(role['credentials'])
            
            # Test each API endpoint
            for endpoint in api_endpoints:
                url = urllib.parse.urljoin(self.target, endpoint)
                
                # Try both GET and POST requests
                for method in ['GET', 'POST']:
                    # For POST, include a simple JSON payload
                    data = None
                    if method == 'POST':
                        data = {'test': 'data'}
                    
                    # Make request with session cookies if available
                    response = make_request(url, method=method, json_data=data, cookies=session_cookies)

                    if response.get('success') and response.get('status_code') == 200:
                        # Check if the response contains sensitive data
                        if self._contains_sensitive_data(response['text']):
                            vulnerability = {
                                'url': url,
                                'type': 'API Access Control',
                                'role': role['name'],
                                'method': method,
                                'description': f"User with role {role['name']} can access API endpoint {endpoint} with {method}",
                                'severity': 'High',
                                'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                            }
                            
                            self.vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential API access control issue found at {url} with {method} for role {role['name']}")
    
    def _authenticate(self, credentials):
        """
        Authenticate with the provided credentials and return session cookies.
        
        Args:
            credentials (dict): Authentication credentials
            
        Returns:
            dict: Session cookies or None if authentication failed
        """
        # Try common login endpoints
        login_endpoints = [
            '/login',
            '/signin',
            '/auth',
            '/auth/login',
            '/api/login',
            '/api/v1/login',
            '/api/v2/login',
            '/api/auth',
            '/api/v1/auth',
            '/api/v2/auth',
            '/user/login',
            '/account/login',
            '/wp-login.php'
        ]
        
        for endpoint in login_endpoints:
            url = urllib.parse.urljoin(self.target, endpoint)
            
            # Try both form and JSON authentication
            for content_type in ['form', 'json']:
                if content_type == 'form':
                    data = {
                        'username': credentials.get('username', ''),
                        'password': credentials.get('password', ''),
                        'email': credentials.get('email', '')
                    }
                    response = make_request(url, method='POST', data=data)
                else:
                    data = {
                        'username': credentials.get('username', ''),
                        'password': credentials.get('password', ''),
                        'email': credentials.get('email', '')
                    }
                    response = make_request(url, method='POST', json_data=data)
                
                if response.get('success'):
                    # Check if we got cookies back
                    if 'cookies' in response and response['cookies']:
                        return response['cookies']
                    
                    # Check if we got a JWT token in the response
                    if 'text' in response:
                        try:
                            json_response = json.loads(response['text'])
                            if 'token' in json_response:
                                # Return the token as a cookie
                                return {'token': json_response['token']}
                        except json.JSONDecodeError:
                            pass
        
        return None
    
    def _contains_sensitive_data(self, content):
        """
        Check if the content contains sensitive data.
        
        Args:
            content (str): Content to check
            
        Returns:
            bool: True if sensitive data is found, False otherwise
        """
        # Patterns for sensitive data
        sensitive_patterns = [
            r'password',
            r'passwd',
            r'pwd',
            r'secret',
            r'token',
            r'api[_\-]?key',
            r'access[_\-]?key',
            r'auth[_\-]?key',
            r'credentials',
            r'private[_\-]?key',
            r'ssn',
            r'social[_\-]?security',
            r'cc[_\-]?number',
            r'credit[_\-]?card',
            r'card[_\-]?number',
            r'cvv',
            r'cvc',
            r'ssn',
            r'address',
            r'email',
            r'phone',
            r'dob',
            r'birth[_\-]?date',
            r'admin',
            r'root',
            r'config',
            r'settings'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _contains_admin_features(self, content):
        """
        Check if the content contains admin features.
        
        Args:
            content (str): Content to check
            
        Returns:
            bool: True if admin features are found, False otherwise
        """
        # Patterns for admin features
        admin_patterns = [
            r'admin',
            r'administrator',
            r'manage users',
            r'manage[_\-]?users',
            r'user[_\-]?management',
            r'user management',
            r'delete user',
            r'delete[_\-]?user',
            r'add user',
            r'add[_\-]?user',
            r'edit user',
            r'edit[_\-]?user',
            r'settings',
            r'configuration',
            r'config',
            r'dashboard',
            r'control panel',
            r'control[_\-]?panel',
            r'admin panel',
            r'admin[_\-]?panel',
            r'superuser',
            r'super[_\-]?user',
            r'root',
            r'privileges',
            r'permission'
        ]
        
        for pattern in admin_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _consolidate_results(self):
        """
        Consolidate and deduplicate vulnerability results.
        
        Returns:
            dict: Consolidated results
        """
        if not self.vulnerabilities:
            return {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'module': self.name,
                'vulnerabilities': [],
                'summary': {
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                }
            }
        
        # Group vulnerabilities by URL and type
        grouped_vulns = {}
        for vuln in self.vulnerabilities:
            key = f"{vuln['url']}|{vuln['type']}"
            if key not in grouped_vulns:
                grouped_vulns[key] = []
            grouped_vulns[key].append(vuln)
        
        # Consolidate each group
        consolidated_vulns = []
        for vulns in grouped_vulns.values():
            # Sort by severity (Critical > High > Medium > Low)
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            vulns.sort(key=lambda v: severity_order.get(v['severity'], 4))
            
            # Take the highest severity vulnerability as the base
            base_vuln = vulns[0].copy()
            
            # If there are multiple roles affected, list them all
            if 'role' in base_vuln:
                roles = set(v['role'] for v in vulns if 'role' in v)
                if len(roles) > 1:
                    base_vuln['roles'] = list(roles)
                    base_vuln.pop('role', None)
            
            # If there are multiple methods affected, list them all
            if 'method' in base_vuln:
                methods = set(v['method'] for v in vulns if 'method' in v)
                if len(methods) > 1:
                    base_vuln['methods'] = list(methods)
                    base_vuln.pop('method', None)
            
            consolidated_vulns.append(base_vuln)
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in consolidated_vulns:
            severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1
        
        # Create the final results
        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'module': self.name,
            'vulnerabilities': consolidated_vulns,
            'summary': {
                'total': len(consolidated_vulns),
                'critical': severity_counts['Critical'],
                'high': severity_counts['High'],
                'medium': severity_counts['Medium'],
                'low': severity_counts['Low']
            }
        }
        
        return results