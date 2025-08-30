#!/usr/bin/env python3

from typing import Dict, List, Optional, Set
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string

class SSTIScanner(VulnerabilityTestingModule):
    """Server-Side Template Injection (SSTI) vulnerability scanner module for PIN0CCHI0."""

    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "ssti_scanner"
        self.description = "Tests for Server-Side Template Injection vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
            "https://portswigger.net/research/server-side-template-injection"
        ]
        self.vulnerabilities = []
        self.visited_urls: Set[str] = set()
        
        # SSTI detection payloads for various template engines
        self.detection_payloads = {
            'generic': [
                '${7*7}',
                '{{7*7}}',
                '<%= 7*7 %>',
                '{7*7}',
                '#{ 7*7 }'
            ],
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{request}}',
                '{{self}}'
            ],
            'django': [
                '{{ 7*7 }}',
                '{% debug %}',
                '{{ request }}'
            ],
            'freemarker': [
                '${7*7}',
                '#{7*7}',
                '<#if 7*7==49>PIN0CCHI0</#if>'
            ],
            'velocity': [
                '#set($x = 7*7)${x}',
                '#if(7*7==49)PIN0CCHI0#end'
            ],
            'thymeleaf': [
                '${7*7}',
                '*{7*7}',
                'th:text=${7*7}'
            ]
        }

    def _extract_inputs(self, url: str, response: requests.Response) -> List[Dict]:
        """Extract all potential SSTI input vectors from the response.

        Args:
            url: Target URL
            response: HTTP response object

        Returns:
            List of dictionaries containing input vector information
        """
        inputs = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract form inputs
            for form in soup.find_all('form'):
                form_action = urljoin(url, form.get('action', ''))
                form_method = form.get('method', 'GET').upper()

                for input_field in form.find_all(['input', 'textarea']):
                    input_type = input_field.get('type', 'text')
                    if input_type not in ['submit', 'button', 'image', 'reset', 'file']:
                        inputs.append({
                            'type': 'form',
                            'method': form_method,
                            'action': form_action,
                            'name': input_field.get('name', ''),
                            'value': input_field.get('value', '')
                        })

            # Extract URL parameters
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                inputs.append({
                    'type': 'url',
                    'method': 'GET',
                    'action': url,
                    'name': param,
                    'value': values[0] if values else ''
                })

        except Exception as e:
            self.logger.error(f"Error extracting inputs: {str(e)}")

        return inputs

    def _detect_template_engine(self, response: requests.Response) -> Optional[str]:
        """Try to detect the template engine based on response characteristics.

        Args:
            response: HTTP response object

        Returns:
            String identifying the template engine if detected, None otherwise
        """
        try:
            # Look for template engine signatures in response headers and content
            headers = response.headers
            content = response.text.lower()

            if 'x-template-engine' in headers:
                engine = headers['x-template-engine'].lower()
                if any(eng in engine for eng in ['jinja', 'django', 'freemarker', 'velocity', 'thymeleaf']):
                    return engine

            # Check for common template engine error patterns
            if 'jinja2.exceptions' in content or 'jinja2.runtime' in content:
                return 'jinja2'
            elif 'django.template' in content or 'django.core' in content:
                return 'django'
            elif 'freemarker.template' in content:
                return 'freemarker'
            elif 'org.apache.velocity' in content:
                return 'velocity'
            elif 'org.thymeleaf' in content:
                return 'thymeleaf'

        except Exception as e:
            self.logger.error(f"Error detecting template engine: {str(e)}")

        return None

    def _test_input_vector(self, input_vector: Dict, template_engine: Optional[str]) -> Optional[Dict]:
        """Test a single input vector for SSTI vulnerabilities.

        Args:
            input_vector: Dictionary containing input vector information
            template_engine: Identified template engine, if any

        Returns:
            Dictionary containing vulnerability details if found, None otherwise
        """
        try:
            # Select payloads based on detected template engine
            payloads = self.detection_payloads['generic']
            if template_engine and template_engine in self.detection_payloads:
                payloads.extend(self.detection_payloads[template_engine])

            for payload in payloads:
                if input_vector['type'] == 'url':
                    # Test URL parameters
                    parsed = urlparse(input_vector['action'])
                    query_params = parse_qs(parsed.query)
                    query_params[input_vector['name']] = [payload]
                    new_query = '&'.join(
                        f"{k}={v[0]}" for k, v in query_params.items()
                    )
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                    response = make_http_request(test_url)
                    if response:
                        # Check for successful template execution
                        if '49' in response.text or 'PIN0CCHI0' in response.text:
                            return {
                                "type": "Server-Side Template Injection",
                                "url": test_url,
                                "parameter": input_vector['name'],
                                "template_engine": template_engine or "Unknown",
                                "payload": payload,
                                "severity": "High",
                                "description": "Parameter vulnerable to template injection",
                                "mitigation": "Avoid passing user input to template rendering functions"
                            }

                elif input_vector['type'] == 'form':
                    # Test form inputs
                    data = {input_vector['name']: payload}
                    response = make_http_request(
                        input_vector['action'],
                        method=input_vector['method'],
                        data=data
                    )

                    if response:
                        # Check for successful template execution
                        if '49' in response.text or 'PIN0CCHI0' in response.text:
                            return {
                                "type": "Server-Side Template Injection",
                                "url": input_vector['action'],
                                "parameter": input_vector['name'],
                                "template_engine": template_engine or "Unknown",
                                "payload": payload,
                                "severity": "High",
                                "description": "Form input vulnerable to template injection",
                                "mitigation": "Avoid passing user input to template rendering functions"
                            }

        except Exception as e:
            self.logger.error(f"Error testing input vector: {str(e)}")

        return None

    def run(self, target: str) -> bool:
        """Run the SSTI scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting SSTI scan on {target}")

        try:
            # Make initial request
            response = make_http_request(target)
            if not response:
                self.logger.error(f"Could not connect to target {target}")
                return False

            # Try to detect template engine
            template_engine = self._detect_template_engine(response)
            if template_engine:
                self.logger.info(f"Detected template engine: {template_engine}")

            # Extract and test input vectors
            input_vectors = self._extract_inputs(target, response)
            for vector in input_vectors:
                vuln = self._test_input_vector(vector, template_engine)
                if vuln:
                    self.vulnerabilities.append(vuln)

            self.logger.info(
                f"SSTI scan completed. Found {len(self.vulnerabilities)} vulnerabilities."
            )
            return True

        except Exception as e:
            self.logger.error(f"Error during SSTI scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the SSTI scanner module."""
        self.logger.info("Cleaning up SSTI scanner module...")
        return True