#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
from urllib.parse import urlparse
from core.base_module import VulnTestingModule
from core.utils import make_http_request

class HTTPSecurityScanner(VulnerabilityTestingModule):
    """HTTP Security Headers and Misconfiguration scanner module for PIN0CCHI0."""

    def __init__(self):
        super().__init__(config)
        self.name = "http_security_scanner"
        self.description = "Tests for missing or misconfigured HTTP security headers"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
        ]
        self.vulnerabilities = []
        self.session = requests.Session()

    def _check_security_headers(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for missing or misconfigured security headers.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        headers = response.headers

        # Content Security Policy
        if 'Content-Security-Policy' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "Content-Security-Policy",
                "severity": "High",
                "description": "No Content Security Policy (CSP) header found",
                "mitigation": "Implement a strong Content Security Policy to prevent XSS and other injection attacks"
            })
        else:
            csp = headers['Content-Security-Policy']
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                findings.append({
                    "type": "Weak Security Header",
                    "header": "Content-Security-Policy",
                    "severity": "Medium",
                    "description": "CSP allows unsafe inline scripts or eval()",
                    "mitigation": "Remove 'unsafe-inline' and 'unsafe-eval' from CSP directives"
                })

        # X-Frame-Options
        if 'X-Frame-Options' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "X-Frame-Options",
                "severity": "Medium",
                "description": "No X-Frame-Options header found",
                "mitigation": "Add X-Frame-Options header to prevent clickjacking attacks"
            })

        # X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "X-Content-Type-Options",
                "severity": "Medium",
                "description": "No X-Content-Type-Options header found",
                "mitigation": "Add X-Content-Type-Options: nosniff header"
            })

        # Strict-Transport-Security
        if url.startswith('https://') and 'Strict-Transport-Security' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "Strict-Transport-Security",
                "severity": "High",
                "description": "No HSTS header found on HTTPS site",
                "mitigation": "Implement HSTS with appropriate max-age"
            })

        # X-XSS-Protection
        if 'X-XSS-Protection' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "X-XSS-Protection",
                "severity": "Low",
                "description": "No X-XSS-Protection header found",
                "mitigation": "Add X-XSS-Protection: 1; mode=block header"
            })

        # Referrer-Policy
        if 'Referrer-Policy' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "Referrer-Policy",
                "severity": "Low",
                "description": "No Referrer-Policy header found",
                "mitigation": "Add Referrer-Policy header with appropriate policy"
            })

        # Permissions-Policy
        if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
            findings.append({
                "type": "Missing Security Header",
                "header": "Permissions-Policy",
                "severity": "Medium",
                "description": "No Permissions-Policy header found",
                "mitigation": "Implement Permissions-Policy to control browser features"
            })

        return findings

    def _check_cookie_security(self, url: str, response: requests.Response) -> List[Dict]:
        """Check for insecure cookie configurations.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        is_https = url.startswith('https://')

        for cookie in response.cookies:
            cookie_findings = []

            # Check Secure flag
            if is_https and not cookie.secure:
                cookie_findings.append("missing Secure flag")

            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_findings.append("missing HttpOnly flag")

            # Check SameSite attribute
            if not any(attr.lower().startswith('samesite') 
                      for attr in cookie._rest.keys()):
                cookie_findings.append("missing SameSite attribute")

            if cookie_findings:
                findings.append({
                    "type": "Insecure Cookie Configuration",
                    "cookie_name": cookie.name,
                    "severity": "Medium",
                    "description": f"Cookie has {', '.join(cookie_findings)}",
                    "mitigation": "Set appropriate security attributes for cookies"
                })

        return findings

    def _check_information_disclosure(self, response: requests.Response) -> List[Dict]:
        """Check for information disclosure in HTTP headers.

        Args:
            response: HTTP response object

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        headers = response.headers

        # Check for server header
        if 'Server' in headers:
            server = headers['Server']
            if re.search(r'[0-9.]+', server):  # Version number detected
                findings.append({
                    "type": "Information Disclosure",
                    "header": "Server",
                    "severity": "Low",
                    "description": f"Server header reveals version information: {server}",
                    "mitigation": "Remove version information from Server header"
                })

        # Check for X-Powered-By header
        if 'X-Powered-By' in headers:
            findings.append({
                "type": "Information Disclosure",
                "header": "X-Powered-By",
                "severity": "Low",
                "description": f"X-Powered-By header reveals technology: {headers['X-Powered-By']}",
                "mitigation": "Remove X-Powered-By header"
            })

        # Check for other common information disclosure headers
        sensitive_headers = [
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Runtime',
            'X-Version',
            'X-Generator'
        ]

        for header in sensitive_headers:
            if header in headers:
                findings.append({
                    "type": "Information Disclosure",
                    "header": header,
                    "severity": "Low",
                    "description": f"{header} header reveals technical information",
                    "mitigation": f"Remove {header} header"
                })

        return findings

    def _check_cors_configuration(self, response: requests.Response) -> List[Dict]:
        """Check for misconfigured CORS headers.

        Args:
            response: HTTP response object

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        headers = response.headers

        if 'Access-Control-Allow-Origin' in headers:
            allowed_origin = headers['Access-Control-Allow-Origin']
            
            if allowed_origin == '*':
                findings.append({
                    "type": "Insecure CORS Configuration",
                    "header": "Access-Control-Allow-Origin",
                    "severity": "Medium",
                    "description": "CORS allows requests from any origin",
                    "mitigation": "Restrict CORS to specific trusted origins"
                })

            # Check for dynamic CORS configuration
            if 'Origin' in response.request.headers:
                request_origin = response.request.headers['Origin']
                if request_origin == allowed_origin:
                    findings.append({
                        "type": "Insecure CORS Configuration",
                        "header": "Access-Control-Allow-Origin",
                        "severity": "High",
                        "description": "CORS configuration reflects Origin header",
                        "mitigation": "Implement strict CORS policy with whitelist"
                    })

        return findings

    def run(self, target: str) -> bool:
        """Run the HTTP security scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting HTTP security scan on {target}")

        try:
            # Make initial request
            response = make_http_request(target, method="GET")
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Perform all security checks
            self.vulnerabilities.extend(self._check_security_headers(target, response))
            self.vulnerabilities.extend(self._check_cookie_security(target, response))
            self.vulnerabilities.extend(self._check_information_disclosure(response))
            self.vulnerabilities.extend(self._check_cors_configuration(response))

            # Test CORS with different origins
            test_origins = [
                'https://evil.com',
                'http://attacker.com',
                'null'
            ]

            for origin in test_origins:
                headers = {'Origin': origin}
                cors_response = make_http_request(target, method="GET", headers=headers)
                if cors_response:
                    self.vulnerabilities.extend(
                        self._check_cors_configuration(cors_response)
                    )

            self.logger.info(
                f"HTTP security scan completed. Found {len(self.vulnerabilities)} issues."
            )
            return True

        except Exception as e:
            self.logger.error(f"Error during HTTP security scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the HTTP security scanner module."""
        self.logger.info("Cleaning up HTTP security scanner module...")
        return True