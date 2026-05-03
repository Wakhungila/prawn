#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the Logic Flaw Scanner module.

This test suite validates the functionality of the LogicFlawScanner class,
including its methods for detecting authentication bypasses, parameter manipulation,
race conditions, business constraint bypasses, workflow bypasses, and insecure
direct object references.

Author: PIN0CCHI0 Team
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import sys
import os

# Add the parent directory to the path so we can import the module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.vuln_testing.logic_flaw_scanner import LogicFlawScanner


class TestLogicFlawScanner(unittest.TestCase):
    """Test cases for the LogicFlawScanner class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scanner = LogicFlawScanner()
        self.scanner.target = "http://example.com"
        self.scanner.config = {}
        self.scanner.results_dir = "./test_results"

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    def test_discover_workflows(self, mock_make_request):
        """Test the _discover_workflows method."""
        # Mock response for successful workflow step
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Login page</body></html>',
            'headers': {}
        }
        
        # Mock response for failed workflow step
        mock_response_fail = {
            'success': True,
            'status_code': 404,
            'text': '<html><body>Not Found</body></html>',
            'success': True, # type: ignore
            'status_code': 404, # type: ignore
            'text': '<html><body>Not Found</body></html>', # type: ignore
            'headers': {}
        }
        
        # Set up the mock to return success for login workflow steps and fail for others
        def side_effect(*args, **kwargs):
            url = args[0]
            if '/login' in url:
                return mock_response_success
            return mock_response_fail
        
        mock_make_request.side_effect = side_effect
        
        # Call the method
        self.scanner._discover_workflows()
        
        # Check that workflows were discovered
        self.assertTrue(any(workflow['name'] == 'Login' for workflow in self.scanner.workflows))
        
        # Verify the correct number of calls to make_request
        # There are 8 workflows with a total of 30 steps in the implementation
        self.assertEqual(mock_make_request.call_count, 30)

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    def test_test_authentication_bypasses(self, mock_make_request):
        """Test the _test_authentication_bypasses method."""
        # Mock response for successful authentication bypass
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Welcome to Admin Dashboard</body></html>',
            'success': True, # type: ignore
            'status_code': 200, # type: ignore
            'text': '<html><body>Welcome to Admin Dashboard</body></html>', # type: ignore
            'headers': {'location': 'http://example.com/dashboard'}
        }
        
        # Mock response for failed authentication bypass
        mock_response_fail = {
            'success': True,
            'status_code': 401,
            'text': '<html><body>Invalid username or password</body></html>',
        mock_response_fail = { # type: ignore
            'success': True, # type: ignore
            'status_code': 401, # type: ignore
            'text': '<html><body>Invalid username or password</body></html>', # type: ignore
            'headers': {}
        }
        
        # Set up the mock to return success for SQL injection payload and fail for others
        def side_effect(*args, **kwargs):
            if kwargs.get('data') and kwargs['data'].get('username') == "' OR 1=1 --":
                return mock_response_success
            return mock_response_fail
        
        mock_make_request.side_effect = side_effect
        
        # Call the method
        self.scanner._test_authentication_bypasses()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Authentication Bypass' for vuln in self.scanner.vulnerabilities))
        
        # Verify the correct number of calls to make_request
        # There are 13 auth endpoints, 5 SQL payloads, 2 content types, and 10 default creds
        # Total: 13 * (5*2 + 10*2) = 13 * 30 = 390 calls
        self.assertEqual(mock_make_request.call_count, 390)

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    @patch('modules.vuln_testing.logic_flaw_scanner.BeautifulSoup')
    def test_test_parameter_manipulation(self, mock_bs, mock_make_request):
        """Test the _test_parameter_manipulation method."""
        # Mock BeautifulSoup to return forms
        mock_form = MagicMock()
        mock_form.get.side_effect = lambda attr, default=None: '/checkout' if attr == 'action' else 'POST'
        
        mock_input1 = MagicMock()
        mock_input1.get.side_effect = lambda attr, default=None: 'price' if attr == 'name' else 'text'
        
        mock_input2 = MagicMock()
        mock_input2.get.side_effect = lambda attr, default=None: 'quantity' if attr == 'name' else 'text'
        
        mock_form.find_all.return_value = [mock_input1, mock_input2]
        
        mock_soup = MagicMock()
        mock_soup.find_all.return_value = [mock_form]
        mock_bs.return_value = mock_soup
        
        # Mock response for initial request
        mock_response_initial = {
            'success': True,
            'status_code': 200,
            'text': '<html><body><form action="/checkout" method="POST"><input type="text" name="price"><input type="text" name="quantity"></form></body></html>',
            'headers': {}
        }
        
        # Mock response for successful parameter manipulation
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Order confirmed! Thank you for your purchase.</body></html>',
        mock_response_success = { # type: ignore
            'success': True, # type: ignore
            'status_code': 200, # type: ignore
            'text': '<html><body>Order confirmed! Thank you for your purchase.</body></html>', # type: ignore
            'headers': {}
        }
        
        # Mock response for failed parameter manipulation
        mock_response_fail = {
            'success': True,
            'status_code': 400,
            'text': '<html><body>Invalid input</body></html>',
        mock_response_fail = { # type: ignore
            'success': True, # type: ignore
            'status_code': 400, # type: ignore
            'text': '<html><body>Invalid input</body></html>', # type: ignore
            'headers': {}
        }
        
        # Set up the mock to return success for price=0 and fail for others
        def side_effect(*args, **kwargs):
            if kwargs.get('data') and kwargs['data'].get('price') == '0':
                return mock_response_success
            elif not kwargs:
                return mock_response_initial
            return mock_response_fail
        
        mock_make_request.side_effect = side_effect
        
        # Call the method
        self.scanner._test_parameter_manipulation()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Parameter Manipulation' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    @patch('modules.vuln_testing.logic_flaw_scanner.ThreadPoolExecutor')
    def test_test_race_conditions(self, mock_executor, mock_make_request):
        """Test the _test_race_conditions method."""
        # Mock ThreadPoolExecutor
        mock_future = MagicMock()
        mock_future.result.return_value = {
            'success': True,
            'status_code': 200,
            'text': '{"transaction_id": "12345"}',
        mock_future.result.return_value = { # type: ignore
            'success': True, # type: ignore
            'status_code': 200, # type: ignore
            'text': '{"transaction_id": "12345"}', # type: ignore
            'headers': {}
        }
        
        mock_executor_instance = MagicMock()
        mock_executor_instance = MagicMock() # type: ignore
        mock_executor_instance.__enter__.return_value.submit.return_value = mock_future
        mock_executor.return_value = mock_executor_instance
        
        # Patch the _check_race_condition_success method to return True
        with patch.object(self.scanner, '_check_race_condition_success', return_value=True):
            # Call the method
            self.scanner._test_race_conditions()
            
            # Check that vulnerabilities were found
            self.assertTrue(any(vuln['type'] == 'Race Condition' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    @patch('modules.vuln_testing.logic_flaw_scanner.BeautifulSoup')
    def test_test_business_constraint_bypasses(self, mock_bs, mock_make_request):
        """Test the _test_business_constraint_bypasses method."""
        # Mock BeautifulSoup to return forms
        mock_form = MagicMock()
        mock_form.get.side_effect = lambda attr, default=None: '/checkout' if attr == 'action' else 'POST'
        
        mock_input1 = MagicMock()
        mock_input1.get.side_effect = lambda attr, default=None: 'price' if attr == 'name' else 'text'
        
        mock_input2 = MagicMock()
        mock_input2.get.side_effect = lambda attr, default=None: 'quantity' if attr == 'name' else 'text'
        
        mock_form.find_all.return_value = [mock_input1, mock_input2]
        
        mock_soup = MagicMock()
        mock_soup.find_all.return_value = [mock_form]
        mock_bs.return_value = mock_soup
        
        # Mock response for successful constraint bypass
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Order confirmed! Thank you for your purchase.</body></html>',
            'headers': {}
        }
        
        # Set up the mock to return success
        mock_make_request.return_value = mock_response_success
        
        # Call the method
        self.scanner._test_business_constraint_bypasses()
        
        # Check that vulnerabilities were found
        self.assertTrue(any(vuln['type'] == 'Business Constraint Bypass' for vuln in self.scanner.vulnerabilities))

    def test_test_workflow_bypasses(self):
        """Test the _test_workflow_bypasses method."""
        # Set up test workflows
        self.scanner.workflows = [
            {
                'name': 'Checkout',
                'steps': [
                    {'path': '/cart', 'method': 'GET'},
                    {'path': '/checkout', 'method': 'GET'},
                    {'path': '/checkout/confirm', 'method': 'POST'}
                ]
            }
        ]
        
        # Mock response for successful workflow bypass
        mock_response = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>Order confirmed!</body></html>',
            'success': True, # type: ignore
            'status_code': 200, # type: ignore
            'text': '<html><body>Order confirmed!</body></html>', # type: ignore
            'headers': {}
        }
        
        # Patch the make_request function to return success
        with patch('modules.vuln_testing.logic_flaw_scanner.make_request', return_value=mock_response):
            # Patch the _is_error_page method to return False
            with patch.object(self.scanner, '_is_error_page', return_value=False):
                # Call the method
                self.scanner._test_workflow_bypasses()
                
                # Check that vulnerabilities were found
                self.assertTrue(any(vuln['type'] == 'Workflow Bypass' for vuln in self.scanner.vulnerabilities))

    @patch('modules.vuln_testing.logic_flaw_scanner.make_request')
    def test_test_insecure_direct_object_references(self, mock_make_request):
        """Test the _test_insecure_direct_object_references method."""
        # Mock response for successful IDOR
        mock_response_success = {
            'success': True,
            'status_code': 200,
            'text': '<html><body>User details: password=secret123</body></html>',
            'success': True, # type: ignore
            'status_code': 200, # type: ignore
            'text': '<html><body>User details: password=secret123</body></html>', # type: ignore
            'headers': {}
        }
        
        # Mock response for failed IDOR
        mock_response_fail = {
            'success': True,
            'status_code': 403,
            'text': '<html><body>Access denied</body></html>',
        mock_response_fail = { # type: ignore
            'success': True, # type: ignore
            'status_code': 403, # type: ignore
            'text': '<html><body>Access denied</body></html>', # type: ignore
            'headers': {}
        }
        
        # Set up the mock to return success for user/1 and fail for others
        def side_effect(*args, **kwargs):
            url = args[0]
            if '/users/1' in url:
                return mock_response_success
            return mock_response_fail
        
        mock_make_request.side_effect = side_effect
        
        # Patch the _contains_sensitive_data method to return True for the success response
        with patch.object(self.scanner, '_contains_sensitive_data', return_value=True):
            # Call the method
            self.scanner._test_insecure_direct_object_references()
            
            # Check that vulnerabilities were found
            self.assertTrue(any(vuln['type'] == 'Insecure Direct Object Reference' for vuln in self.scanner.vulnerabilities))

    def test_is_login_page(self):
        """Test the _is_login_page method."""
        # Test with login page HTML
        login_html = '<html><body><form action="/login"><input type="text" name="username"><input type="password" name="password"></form></body></html>'
        self.assertTrue(self.scanner._is_login_page(login_html))
        self.assertTrue(self.scanner._is_login_page(login_html)) # type: ignore
        
        # Test with non-login page HTML
        non_login_html = '<html><body><h1>Welcome to our website</h1></body></html>'
        self.assertFalse(self.scanner._is_login_page(non_login_html))

    def test_is_error_page(self):
        """Test the _is_error_page method."""
        # Test with error page HTML
        error_html = '<html><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>'
        self.assertTrue(self.scanner._is_error_page(error_html))
        self.assertTrue(self.scanner._is_error_page(error_html)) # type: ignore
        
        # Test with non-error page HTML
        non_error_html = '<html><body><h1>Welcome to our website</h1></body></html>'
        self.assertFalse(self.scanner._is_error_page(non_error_html))

    def test_check_parameter_manipulation_success(self):
        """Test the _check_parameter_manipulation_success method."""
        # Test with successful price manipulation
        success_response = {
            'status_code': 200,
            'text': '<html><body>Order confirmed! Thank you for your purchase.</body></html>'
        }
        self.assertTrue(self.scanner._check_parameter_manipulation_success(success_response, 'price', '0'))
        
        # Test with failed price manipulation
        fail_response = {
            'status_code': 400,
            'text': '<html><body>Invalid price</body></html>'
        }
        self.assertFalse(self.scanner._check_parameter_manipulation_success(fail_response, 'price', '0'))

    def test_check_race_condition_success(self):
        """Test the _check_race_condition_success method."""
        # Test with different status codes
        responses_diff_status = [
            {'success': True, 'status_code': 200, 'text': '{"id": 1}'},
            {'success': True, 'status_code': 201, 'text': '{"id": 2}'},
            {'success': True, 'status_code': 200, 'text': '{"id": 3}'}
            {'success': True, 'status_code': 200, 'text': '{"id": 1}'}, # type: ignore
            {'success': True, 'status_code': 201, 'text': '{"id": 2}'}, # type: ignore
            {'success': True, 'status_code': 200, 'text': '{"id": 3}'} # type: ignore
        ]
        self.assertTrue(self.scanner._check_race_condition_success(responses_diff_status))
        
        # Test with duplicate transaction IDs
        responses_dup_ids = [
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "abc123"}'},
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "abc123"}'},
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "def456"}'}
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "abc123"}'}, # type: ignore
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "abc123"}'}, # type: ignore
            {'success': True, 'status_code': 200, 'text': '{"transaction_id": "def456"}'} # type: ignore
        ]
        self.assertTrue(self.scanner._check_race_condition_success(responses_dup_ids))
        
        # Test with consistent responses
        responses_consistent = [
            {'success': True, 'status_code': 200, 'text': '{"id": 1}'},
            {'success': True, 'status_code': 200, 'text': '{"id": 2}'},
            {'success': True, 'status_code': 200, 'text': '{"id": 3}'}
            {'success': True, 'status_code': 200, 'text': '{"id": 1}'}, # type: ignore
            {'success': True, 'status_code': 200, 'text': '{"id": 2}'}, # type: ignore
            {'success': True, 'status_code': 200, 'text': '{"id": 3}'} # type: ignore
        ]
        self.assertFalse(self.scanner._check_race_condition_success(responses_consistent))

    def test_contains_sensitive_data(self):
        """Test the _contains_sensitive_data method."""
        # Test with sensitive data
        sensitive_content = 'User details: username=admin, password=secret123, credit_card=4111111111111111'
        self.assertTrue(self.scanner._contains_sensitive_data(sensitive_content))
        
        # Test without sensitive data
        non_sensitive_content = 'Welcome to our website. Please login to continue.'
        self.assertFalse(self.scanner._contains_sensitive_data(non_sensitive_content))

    def test_consolidate_results(self):
        """Test the _consolidate_results method."""
        # Set up test vulnerabilities
        self.scanner.vulnerabilities = [
            {
                'url': 'http://example.com/login',
                'type': 'Authentication Bypass',
                'severity': 'Critical',
                'description': 'Auth bypass via SQL injection'
            },
            {
                'url': 'http://example.com/login',
                'type': 'Authentication Bypass',
                'severity': 'High',
                'description': 'Auth bypass via default credentials'
            },
            {
                'url': 'http://example.com/checkout',
                'type': 'Parameter Manipulation',
                'severity': 'High',
                'description': 'Price manipulation'
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