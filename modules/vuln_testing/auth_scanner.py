#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
import time
from bs4 import BeautifulSoup # type: ignore
from urllib.parse import urljoin, urlparse
from core.base_module import VulnTestingModule
from core.utils import make_http_request, generate_random_string

class AuthScanner(VulnTestingModule):
    """Authentication and Session Management vulnerability scanner module for PIN0CCHI0."""

    def __init__(self):
        super().__init__(name="auth_scanner", description="Tests for authentication and session management vulnerabilities")
        self.description = "Tests for authentication and session management vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
        ]
        self.vulnerabilities = []
        self.session = requests.Session()

    def _find_login_form(self, url: str, response: requests.Response) -> Optional[Dict]:
        """Find login form in the response.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            Dictionary containing login form information if found, None otherwise
        """
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                # Look for common login form indicators
                if any(term in str(form).lower() for term in ['login', 'signin', 'auth']):
                    form_info = {
                        'action': urljoin(url, form.get('action', '')),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }

                    # Get all input fields
                    for input_field in form.find_all(['input', 'select']):
                        input_info = {
                            'name': input_field.get('name', ''),
                            'type': input_field.get('type', 'text'),
                            'id': input_field.get('id', ''),
                            'required': input_field.get('required', False)
                        }
                        form_info['inputs'].append(input_info)

                    return form_info
            return None

        except Exception as e:
            self.logger.error(f"Error finding login form: {str(e)}")
            return None

    def _test_brute_force_protection(self, form: Dict) -> Optional[Dict]:
        """Test for brute force protection.

        Args:
            form: Dictionary containing login form information

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            username_field = next(
                (input_['name'] for input_ in form['inputs'] 
                 if input_['type'] in ['text', 'email']), None
            )
            password_field = next(
                (input_['name'] for input_ in form['inputs'] 
                 if input_['type'] == 'password'), None
            )

            if not (username_field and password_field):
                return None

            # Try multiple rapid login attempts
            attempt_count = 10
            for i in range(attempt_count):
                data = {
                    username_field: f'test_user_{i}',
                    password_field: 'wrong_password'
                }

                response = make_http_request(
                    form['action'],
                    method=form['method'],
                    data=data
                )

                if not response or response.get('status_code') == 429:
                    # Rate limiting detected
                    return None

            return {
                "type": "Missing Brute Force Protection",
                "url": form['action'],
                "severity": "High",
                "description": f"No rate limiting detected after {attempt_count} rapid login attempts",
                "mitigation": "Implement rate limiting, account lockout, or CAPTCHA"
            }

        except Exception as e:
            self.logger.error(f"Error testing brute force protection: {str(e)}")
            return None

    def _test_password_policy(self, form: Dict) -> List[Dict]:
        """Test password policy enforcement.

        Args:
            form: Dictionary containing login form information

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []
        weak_passwords = [
            'password',
            '123456',
            'qwerty',
            'letmein',
            'admin123'
        ]

        try:
            password_field = next(
                (input_['name'] for input_ in form['inputs'] 
                 if input_['type'] == 'password'), None
            )

            if not password_field:
                return findings

            # Test weak password acceptance
            for password in weak_passwords:
                data = {password_field: password}
                if any(input_['type'] in ['text', 'email'] for input_ in form['inputs']):
                    data[next(input_['name'] for input_ in form['inputs'] 
                             if input_['type'] in ['text', 'email'])] = 'test_user'

                response = make_http_request(
                    form['action'],
                    method=form['method'],
                    data=data
                )

                if response and 'password' not in response.get('text', '').lower():
                    findings.append({
                        "type": "Weak Password Policy",
                        "url": form['action'],
                        "severity": "Medium",
                        "description": f"Application accepts weak password: {password}",
                        "mitigation": "Implement strong password requirements"
                    })
                    break

        except Exception as e:
            self.logger.error(f"Error testing password policy: {str(e)}")

        return findings

    def _test_session_management(self, url: str) -> List[Dict]:
        """Test session management security.

        Args:
            url: Target URL

        Returns:
            List of dictionaries containing vulnerability details
        """
        findings = []

        try:
            # Make initial request to get session cookie
            response = make_http_request(url)
            if not response:
                return findings

            session_cookie = None
            for cookie in response.cookies:
                if any(term in cookie.name.lower() 
                       for term in ['session', 'token', 'auth']):
                    session_cookie = cookie
                    break

            if session_cookie:
                # Check cookie security attributes
                if not session_cookie.secure:
                    findings.append({
                        "type": "Insecure Session Cookie",
                        "cookie_name": session_cookie.name,
                        "severity": "High",
                        "description": "Session cookie missing Secure flag",
                        "mitigation": "Set Secure flag on session cookies"
                    })

                if not session_cookie.has_nonstandard_attr('HttpOnly'):
                    findings.append({
                        "type": "Insecure Session Cookie",
                        "cookie_name": session_cookie.name,
                        "severity": "Medium",
                        "description": "Session cookie missing HttpOnly flag",
                        "mitigation": "Set HttpOnly flag on session cookies"
                    })

                # Check session fixation
                old_session = session_cookie.value
                login_response = make_http_request(url)
                if login_response:
                    new_session = None
                    for cookie in login_response.cookies:
                        if cookie.get('name') == session_cookie.get('name'):
                            new_session = cookie.value
                            break

                    if new_session and new_session == old_session:
                        findings.append({
                            "type": "Session Fixation",
                            "severity": "High",
                            "description": "Session ID not changed after login",
                            "mitigation": "Generate new session ID after authentication"
                        })

        except Exception as e:
            self.logger.error(f"Error testing session management: {str(e)}")

        return findings

    def _test_remember_me(self, form: Dict) -> Optional[Dict]:
        """Test 'Remember Me' functionality security.

        Args:
            form: Dictionary containing login form information

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            remember_me = next(
                (input_ for input_ in form['inputs'] 
                 if any(term in str(input_).lower() for term in ['remember', 'persistent'])), 
                None
            )

            if remember_me:
                # Check if remember me token is secure
                response = make_http_request(
                    form['action'],
                    method=form['method'],
                    data={remember_me['name']: 'on'}
                )

                if response and response.get('success'):
                    for cookie in response.cookies:
                        if any(term in cookie.name.lower() 
                               for term in ['remember', 'persistent']):
                            if not (cookie.secure and 
                                   cookie.has_nonstandard_attr('HttpOnly')):
                                return {
                                    "type": "Insecure Remember Me",
                                    "severity": "Medium",
                                    "description": "Remember Me cookie lacks security attributes",
                                    "mitigation": "Set Secure and HttpOnly flags on persistent cookies"
                                }

        except Exception as e:
            self.logger.error(f"Error testing remember me: {str(e)}")

        return None

    def run(self, target: str) -> bool:
        """Run the authentication scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting authentication scan on {target}")

        try:
            # Make initial request
            response = make_http_request(target)
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Find login form
            form = self._find_login_form(target, response)
            if not form:
                self.logger.info("No login form found")
                return True

            # Run all authentication tests
            brute_force_vuln = self._test_brute_force_protection(form)
            if brute_force_vuln:
                self.vulnerabilities.append(brute_force_vuln)

            self.vulnerabilities.extend(self._test_password_policy(form))
            self.vulnerabilities.extend(self._test_session_management(target))

            remember_me_vuln = self._test_remember_me(form)
            if remember_me_vuln:
                self.vulnerabilities.append(remember_me_vuln)

            self.logger.info(
                f"Authentication scan completed. Found {len(self.vulnerabilities)} vulnerabilities."
            )
            return True

        except Exception as e:
            self.logger.error(f"Error during authentication scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the authentication scanner module."""
        self.logger.info("Cleaning up authentication scanner module...")
        return True