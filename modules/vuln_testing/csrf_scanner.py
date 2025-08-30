#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string

class CSRFScanner(VulnerabilityTestingModule):
    """Cross-Site Request Forgery (CSRF) vulnerability scanner module for PIN0CCHI0."""

    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "csrf_scanner"
        self.description = "Tests for Cross-Site Request Forgery (CSRF) vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-community/attacks/csrf",
            "https://portswigger.net/web-security/csrf"
        ]
        self.vulnerabilities = []
        self.session = requests.Session()
        self.csrf_tokens = set()
        self.common_csrf_names = self._get_common_csrf_names()

    def _get_common_csrf_names(self) -> List[str]:
        """Get list of common CSRF token names.

        Returns:
            List of common CSRF token names
        """
        return [
            'csrf', 'csrftoken', 'csrf_token', 'csrf-token',
            'xsrf', 'xsrftoken', 'xsrf_token', 'xsrf-token',
            'anti-csrf', 'anticsrf', '_csrf', '_token',
            '__RequestVerificationToken', 'token', 'authenticity_token'
        ]

    def _find_forms(self, url: str, response: requests.Response) -> List[Dict]:
        """Find forms in the response that might be vulnerable to CSRF.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing form information
        """
        forms = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_info = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': [],
                    'csrf_token': None
                }

                # Get all input fields
                for input_field in form.find_all(['input', 'select', 'textarea']):
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', 'text')
                    input_value = input_field.get('value', '')

                    # Check if this input might be a CSRF token
                    if any(token_name in input_name.lower() for token_name in self.common_csrf_names):
                        form_info['csrf_token'] = {
                            'name': input_name,
                            'value': input_value
                        }
                        self.csrf_tokens.add(input_name)
                    else:
                        form_info['inputs'].append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_value
                        })

                forms.append(form_info)

        except Exception as e:
            self.logger.error(f"Error finding forms: {str(e)}")

        return forms

    def _check_csrf_headers(self, response: requests.Response) -> Dict:
        """Check for CSRF-related security headers.

        Args:
            response: HTTP response object

        Returns:
            Dictionary containing header analysis results
        """
        headers = response.headers
        results = {
            'has_samesite': False,
            'has_csrf_cookie': False,
            'secure_cookie': False,
            'httponly_cookie': False
        }

        # Check cookies
        if 'Set-Cookie' in headers:
            cookies = headers.get('Set-Cookie').lower()
            results['has_samesite'] = 'samesite' in cookies
            results['secure_cookie'] = 'secure' in cookies
            results['httponly_cookie'] = 'httponly' in cookies
            results['has_csrf_cookie'] = any(token_name in cookies 
                                            for token_name in self.common_csrf_names)

        return results

    def _test_csrf_protection(self, form: Dict) -> Optional[Dict]:
        """Test a form for CSRF vulnerabilities.

        Args:
            form: Dictionary containing form information

        Returns:
            Dict containing vulnerability details if found, None otherwise
        """
        try:
            # Skip GET forms as they shouldn't modify state
            if form['method'] == 'GET':
                return None

            # Prepare test data
            test_data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'hidden']:
                    test_data[input_field['name']] = 'test_value'
                elif input_field['type'] == 'email':
                    test_data[input_field['name']] = 'test@example.com'
                elif input_field['type'] == 'password':
                    test_data[input_field['name']] = 'TestPassword123!'
                else:
                    test_data[input_field['name']] = input_field['value']

            # Test 1: Submit without CSRF token
            if form['csrf_token']:
                response1 = make_http_request(
                    form['action'],
                    method=form['method'],
                    data=test_data
                )

                # Test 2: Submit with invalid CSRF token
                test_data[form['csrf_token']['name']] = 'invalid_token'
                response2 = make_http_request(
                    form['action'],
                    method=form['method'],
                    data=test_data
                )

                # If either request succeeds, might be vulnerable
                if (response1 and response1.status_code == 200) or \
                   (response2 and response2.status_code == 200):
                    return {
                        "type": "Cross-Site Request Forgery (CSRF)",
                        "url": form['action'],
                        "method": form['method'],
                        "evidence": "Form submission successful without valid CSRF token",
                        "severity": "High",
                        "description": "Application accepts form submissions without proper CSRF protection",
                        "mitigation": "Implement proper CSRF tokens and validate them server-side"
                    }

            # If no CSRF token found at all
            else:
                # Generate proof-of-concept HTML
                poc_html = self._generate_csrf_poc(form, test_data)
                return {
                    "type": "Cross-Site Request Forgery (CSRF)",
                    "url": form['action'],
                    "method": form['method'],
                    "evidence": "No CSRF token found in form",
                    "severity": "High",
                    "description": "Application lacks CSRF protection mechanism",
                    "mitigation": "Implement CSRF tokens and validate them server-side",
                    "poc": poc_html
                }

        except Exception as e:
            self.logger.error(f"Error testing CSRF protection: {str(e)}")

        return None

    def _generate_csrf_poc(self, form: Dict, test_data: Dict) -> str:
        """Generate proof-of-concept HTML for CSRF attack.

        Args:
            form: Dictionary containing form information
            test_data: Dictionary containing test form data

        Returns:
            HTML string containing CSRF PoC
        """
        poc = f"""<html>
<body>
<h3>CSRF Proof of Concept</h3>
<form id='csrf-form' action='{form['action']}' method='{form['method']}'>
"""

        for field_name, field_value in test_data.items():
            poc += f"<input type='hidden' name='{field_name}' value='{field_value}'>"

        poc += """
</form>
<script>
    document.getElementById('csrf-form').submit();
</script>
</body>
</html>"""

        return poc

    def run(self, target: str) -> bool:
        """Run the CSRF scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting CSRF scan on {target}")

        try:
            # First, make a request to the target
            response = make_http_request(target, method="GET")
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Check security headers
            header_results = self._check_csrf_headers(response)
            if not any(header_results.values()):
                self.vulnerabilities.append({
                    "type": "Missing CSRF Security Headers",
                    "url": target,
                    "evidence": "No CSRF-related security headers found",
                    "severity": "Medium",
                    "description": "Application lacks security headers that help prevent CSRF attacks",
                    "mitigation": "Implement SameSite cookie attribute and other security headers"
                })

            # Find and test forms
            forms = self._find_forms(target, response)
            self.logger.info(f"Found {len(forms)} forms to test")

            for form in forms:
                result = self._test_csrf_protection(form)
                if result:
                    self.vulnerabilities.append(result)

            self.logger.info(f"CSRF scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return True

        except Exception as e:
            self.logger.error(f"Error during CSRF scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the CSRF scanner module."""
        self.logger.info("Cleaning up CSRF scanner module...")
        return True