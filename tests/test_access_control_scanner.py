#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the Access Control Scanner module.

This test suite validates the functionality of the AccessControlScanner class,
including its methods for detecting missing access controls, privilege escalation,
and insecure direct object references.

Author: PIN0CCHI0 Team
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add the parent directory to the path so we can import the module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.vuln_testing.access_control_scanner import AccessControlScanner


class TestAccessControlScanner(unittest.TestCase):
    """Test cases for the AccessControlScanner class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scanner = AccessControlScanner()
        self.scanner.target = "http://example.com"
        self.scanner.config = {}
        self.scanner.results_dir = "./test_results"

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_discover_protected_endpoints(self, mock_make_request):
        """Test the _discover_protected_endpoints method."""
        # Mock response for successful endpoint discovery
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Welcome to Admin Dashboard</body></html>',
            'headers': {}
        }
        
        # Mock response for unauthorized endpoint
        mock_response_unauth = {
            'success': True,
            'status_code': 401,
            'text': '<html><body>Unauthorized</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return unauthorized for admin endpoints
        def side_effect(*args, **kwargs):
            url = args[0]
            if '/admin' in url:
                return mock_response_unauth
            return mock_response_success
        
        mock_make_request.side_effect = side_effect
        
        # Call the method
        self.scanner._discover_protected_endpoints()
        
        # Check that protected endpoints were discovered
        self.assertTrue(any('/admin' in endpoint for endpoint in self.scanner.protected_endpoints))

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_test_horizontal_privilege_escalation(self, mock_make_request):
        """Test the _test_horizontal_privilege_escalation method."""
        # Set up test protected endpoints
        self.scanner.protected_endpoints = [
            {'url': 'http://example.com/users/123/profile', 'method': 'GET', 'status_code': 200}
        ]
        
        # Mock response for successful access
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>User Profile: John Doe</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_horizontal_privilege_escalation()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Horizontal Privilege Escalation' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_test_vertical_privilege_escalation(self, mock_make_request):
        """Test the _test_vertical_privilege_escalation method."""
        # Set up test protected endpoints
        self.scanner.protected_endpoints = [
            {'url': 'http://example.com/admin/users', 'method': 'GET', 'status_code': 401}
        ]
        
        # Mock response for successful access
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Admin Dashboard</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_vertical_privilege_escalation()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Vertical Privilege Escalation' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_test_missing_function_level_access_control(self, mock_make_request):
        """Test the _test_missing_function_level_access_control method."""
        # Mock response for successful access
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Operation completed successfully</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_missing_function_level_access_control()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Missing Function Level Access Control' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_test_forced_browsing(self, mock_make_request):
        """Test the _test_forced_browsing method."""
        # Mock response for successful access
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Sensitive information</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_forced_browsing()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Forced Browsing' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.access_control_scanner.make_request')
    def test_test_api_access_control(self, mock_make_request):
        """Test the _test_api_access_control method."""
        # Mock response for successful access
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '{"users": [{"id": 1, "username": "admin", "role": "admin"}]}',
            'headers': {'Content-Type': 'application/json'}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_api_access_control()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'API Access Control Bypass' for vuln in self.scanner.vulnerabilities))

    def test_is_admin_page(self):
        """Test the _is_admin_page method."""
        # Test with admin page HTML
        admin_html = '<html><body><h1>Admin Dashboard</h1><div>User Management</div></body></html>'
        self.assertTrue(self.scanner._is_admin_page(admin_html))
        
        # Test with non-admin page HTML
        non_admin_html = '<html><body><h1>Welcome to our website</h1></body></html>'
        self.assertFalse(self.scanner._is_admin_page(non_admin_html))

    def test_is_sensitive_data(self):
        """Test the _is_sensitive_data method."""
        # Test with sensitive data
        sensitive_content = 'User details: username=admin, password=secret123, credit_card=4111111111111111'
        self.assertTrue(self.scanner._is_sensitive_data(sensitive_content))
        
        # Test without sensitive data
        non_sensitive_content = 'Welcome to our website. Please login to continue.'
        self.assertFalse(self.scanner._is_sensitive_data(non_sensitive_content))

    def test_consolidate_results(self):
        """Test the _consolidate_results method."""
        # Set up test vulnerabilities
        self.scanner.vulnerabilities = [
            {
                'url': 'http://example.com/admin',
                'type': 'Vertical Privilege Escalation',
                'severity': 'Critical',
                'description': 'Admin access without proper authentication'
            },
            {
                'url': 'http://example.com/admin',
                'type': 'Vertical Privilege Escalation',
                'severity': 'High',
                'description': 'Admin access with parameter manipulation'
            },
            {
                'url': 'http://example.com/users/123',
                'type': 'Horizontal Privilege Escalation',
                'severity': 'High',
                'description': 'Access to another user\'s data'
            }
        ]
        
        # Call the method
        results = self.scanner._consolidate_results()
        
        # Check the results
        self.assertEqual(results['target'], 'http://example.com')
        self.assertEqual(len(results['vulnerabilities']), 2)  # Consolidated from 3 to 2
        self.assertEqual(results['summary']['total'], 2)
        self.assertEqual(results['summary']['critical'], 1)
        self.assertEqual(results['summary']['high'], 1)


if __name__ == '__main__':
    unittest.main()