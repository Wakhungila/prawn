#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
import requests
import re
import base64
import pickle
import json
import yaml
from core.base_module import VulnerabilityTestingModule
from core.utils import make_http_request, generate_random_string

class DeserializationScanner(VulnTestingModule):
    """Insecure Deserialization vulnerability scanner module for PIN0CCHI0."""

    def __init__(self, config: Dict):
        super().__init__(config)
        self.name = "deserialization_scanner"
        self.description = "Tests for Insecure Deserialization vulnerabilities"
        self.author = "PIN0CCHI0 Framework"
        self.references = [
            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
            "https://portswigger.net/web-security/deserialization"
        ]
        self.vulnerabilities = []
        self.serialization_patterns = {
            'python_pickle': rb'\x80\x03',
            'python_marshal': rb'\x00\x00\x00\x00',
            'java': rb'\xac\xed\x00\x05',
            'php_serialize': rb'[OoNbais]:\d+:',
            'node_serialize': rb'^\{.*\}$',
            'ruby_marshal': rb'\x04\x08',
        }
        self.test_payloads = self._generate_test_payloads()

    def _generate_test_payloads(self) -> Dict[str, List[str]]:
        """Generate test payloads for different serialization formats.

        Returns:
            Dict containing payloads for each format
        """
        random_str = generate_random_string(8)
        command = f'echo {random_str}'
        
        return {
            'python_pickle': [
                base64.b64encode(pickle.dumps({'data': command})).decode(),
                base64.b64encode(pickle.dumps({'user_id': 1, 'role': 'admin'})).decode()
            ],
            'php_serialize': [
                f'O:8:"stdClass":1:{{s:4:"data";s:{len(command)}:"{command}"}}',
                'O:8:"stdClass":2:{s:7:"user_id";i:1;s:4:"role";s:5:"admin"}'
            ],
            'node_serialize': [
                json.dumps({'data': command, '__proto__': {'shell': True}}),
                json.dumps({'user_id': 1, 'role': 'admin', 'constructor': {'prototype': {'admin': True}}})
            ],
            'yaml': [
                f'!!python/object/apply:os.system [\'{command}\']',
                '!!python/object/new:type {args: [\"y\", (), {\"admin\": true}]}'
            ]
        }

    def detect_serialization_format(self, data: str) -> Optional[str]:
        """Detect the serialization format of the given data.

        Args:
            data: The data to analyze

        Returns:
            String indicating the detected format, or None if not detected
        """
        try:
            # Try to decode base64 first
            decoded = base64.b64decode(data)
            for format_name, pattern in self.serialization_patterns.items():
                if re.match(pattern, decoded):
                    return format_name
        except:
            # If not base64, check raw patterns
            for format_name, pattern in self.serialization_patterns.items():
                if re.search(pattern, data.encode()):
                    return format_name

        # Check if it's valid JSON
        try:
            json.loads(data)
            return 'json'
        except:
            pass

        # Check if it's valid YAML
        try:
            yaml.safe_load(data)
            return 'yaml'
        except:
            pass

        return None

    def test_parameter(self, url: str, param: str, method: str = "GET", data: Dict = None) -> Optional[Dict]:
        """Test a single parameter for deserialization vulnerabilities.

        Args:
            url: Target URL
            param: Parameter to test
            method: HTTP method (GET/POST)
            data: POST data if applicable

        Returns:
            Dict containing vulnerability details if found, None otherwise
        """
        original_value = data.get(param, '') if data else ''
        detected_format = self.detect_serialization_format(original_value)

        if not detected_format:
            return None

        for payload in self.test_payloads.get(detected_format, []):
            try:
                test_url = url
                if method.upper() == "GET":
                    if "?" in url:
                        test_url = f"{url}&{param}={payload}"
                    else:
                        test_url = f"{url}?{param}={payload}"
                    response = make_http_request(test_url, method="GET", headers=self.config.get("headers", {}))
                else:
                    post_data = data.copy() if data else {}
                    post_data[param] = payload
                    response = make_http_request(url, method="POST", data=post_data, headers=self.config.get("headers", {}))

                if response:
                    # Check for signs of successful exploitation
                    if any([
                        response.status_code == 500,  # Server error might indicate successful exploitation
                        'admin' in response.text.lower(),  # Privilege escalation check
                        'root' in response.text.lower(),  # Command execution check
                        response.headers.get('X-Powered-By', '').lower() != original_value.lower()  # Changed server state
                    ]):
                        return {
                            "type": "Insecure Deserialization",
                            "url": url,
                            "parameter": param,
                            "method": method,
                            "format": detected_format,
                            "payload": payload,
                            "severity": "High",
                            "description": f"Insecure Deserialization vulnerability found in {param} parameter using {detected_format} format",
                            "mitigation": "Implement secure deserialization practices and input validation"
                        }

            except Exception as e:
                self.logger.error(f"Error testing deserialization payload: {str(e)}")

        return None

    def discover_parameters(self, url: str) -> Tuple[List[str], Dict]:
        """Discover parameters that might be vulnerable to insecure deserialization.

        Args:
            url: Target URL

        Returns:
            Tuple of (GET parameters list, POST form data dict)
        """
        get_params = []
        post_data = {}

        try:
            response = make_http_request(url, method="GET", headers=self.config.get("headers", {}))
            if response:
                # Look for serialized data in cookies
                for cookie in response.cookies:
                    if self.detect_serialization_format(cookie.value):
                        get_params.append(cookie.name)

                # Look for serialized data in response body
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check hidden inputs
                for hidden in soup.find_all('input', type='hidden'):
                    value = hidden.get('value', '')
                    if value and self.detect_serialization_format(value):
                        name = hidden.get('name')
                        if name:
                            post_data[name] = value

                # Check data attributes
                for elem in soup.find_all(attrs={'data-serialized': True}):
                    value = elem.get('data-value', '')
                    if value and self.detect_serialization_format(value):
                        name = elem.get('data-name')
                        if name:
                            post_data[name] = value

        except Exception as e:
            self.logger.error(f"Error discovering parameters: {str(e)}")

        return get_params, post_data

    def run(self, target: str) -> bool:
        """Run the deserialization scanner module.

        Args:
            target: Target URL or domain

        Returns:
            bool: True if the scan completed successfully
        """
        self.logger.info(f"Starting deserialization scan on {target}")

        try:
            # Discover parameters to test
            get_params, post_data = self.discover_parameters(target)

            # Test GET parameters
            for param in get_params:
                result = self.test_parameter(target, param, method="GET")
                if result:
                    self.vulnerabilities.append(result)

            # Test POST parameters
            for param, value in post_data.items():
                result = self.test_parameter(target, param, method="POST", data=post_data)
                if result:
                    self.vulnerabilities.append(result)

            # Test common parameter names
            common_params = ['data', 'object', 'serialized', 'state', 'session', 'profile']
            for param in common_params:
                if param not in get_params:
                    result = self.test_parameter(target, param, method="GET")
                    if result:
                        self.vulnerabilities.append(result)

            self.logger.info(f"Deserialization scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
            return True

        except Exception as e:
            self.logger.error(f"Error during deserialization scan: {str(e)}")
            return False

    def cleanup(self) -> bool:
        """Clean up the deserialization scanner module."""
        self.logger.info("Cleaning up deserialization scanner module...")
        return True