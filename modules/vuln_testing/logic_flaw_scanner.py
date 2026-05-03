#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logic Flaw Scanner Module for PIN0CCHI0

This module tests for business logic flaws and insecure design issues including:
- Authentication bypasses
- Authorization flaws
- Race conditions
- Insecure direct object references
- Parameter manipulation
- Business constraint bypasses
- Workflow bypasses

Author: PIN0CCHI0 Team
Version: 1.0
"""

import re
import json
import time
import logging
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

from core.base_module import BaseModule
from core.utils import make_request, save_json_output

# Configure logger
logger = logging.getLogger('pin0cchi0.vuln_testing.logic_flaw_scanner')

class LogicFlawScanner(BaseModule):
    """
    Scanner for detecting business logic flaws and insecure design in web applications.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Logic Flaw Scanner"
        self.description = "Tests for business logic flaws and insecure design in web applications"
        self.category = "Vulnerability Testing"
        self.vulnerabilities = []
        self.workflows = []
        self.results_dir = None
        
    def run(self, target, config=None):
        """
        Run the logic flaw scanner against the target.
        
        Args:
            target (str): The target URL or domain
            config (dict): Configuration options
        
        Returns:
            dict: Results of the scan
        """
        logger.info(f"Starting logic flaw scan on {target}")
        
        self.target = target
        self.config = config or {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = self.config.get('output_dir', './results')
        
        # Discover workflows
        self._discover_workflows()
        
        # Test for authentication bypasses
        self._test_authentication_bypasses()
        
        # Test for parameter manipulation
        self._test_parameter_manipulation()
        
        # Test for race conditions
        self._test_race_conditions()
        
        # Test for business constraint bypasses
        self._test_business_constraint_bypasses()
        
        # Test for workflow bypasses
        self._test_workflow_bypasses()
        
        # Test for insecure direct object references
        self._test_insecure_direct_object_references()
        
        # Consolidate results
        results = self._consolidate_results()
        
        # Save results
        output_file = f"{self.results_dir}/logic_flaw_scan_{timestamp}.json"
        save_json_output(output_file, results)
        
        logger.info(f"Logic flaw scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        
        return results
    
    def _discover_workflows(self):
        """
        Discover common workflows in the application.
        """
        logger.info("Discovering workflows")
        
        # Common workflows to check
        common_workflows = [
            {
                'name': 'Registration',
                'steps': [
                    {'path': '/register', 'method': 'GET'},
                    {'path': '/register', 'method': 'POST'}
                ]
            },
            {
                'name': 'Login',
                'steps': [
                    {'path': '/login', 'method': 'GET'},
                    {'path': '/login', 'method': 'POST'}
                ]
            },
            {
                'name': 'Password Reset',
                'steps': [
                    {'path': '/forgot-password', 'method': 'GET'},
                    {'path': '/forgot-password', 'method': 'POST'},
                    {'path': '/reset-password', 'method': 'GET'},
                    {'path': '/reset-password', 'method': 'POST'}
                ]
            },
            {
                'name': 'Checkout',
                'steps': [
                    {'path': '/cart', 'method': 'GET'},
                    {'path': '/checkout', 'method': 'GET'},
                    {'path': '/checkout/address', 'method': 'POST'},
                    {'path': '/checkout/payment', 'method': 'GET'},
                    {'path': '/checkout/payment', 'method': 'POST'},
                    {'path': '/checkout/confirm', 'method': 'GET'},
                    {'path': '/checkout/confirm', 'method': 'POST'}
                ]
            },
            {
                'name': 'Profile Update',
                'steps': [
                    {'path': '/profile', 'method': 'GET'},
                    {'path': '/profile/edit', 'method': 'GET'},
                    {'path': '/profile/update', 'method': 'POST'}
                ]
            },
            {
                'name': 'Order Creation',
                'steps': [
                    {'path': '/orders/new', 'method': 'GET'},
                    {'path': '/orders/create', 'method': 'POST'}
                ]
            },
            {
                'name': 'Item Creation',
                'steps': [
                    {'path': '/items/new', 'method': 'GET'},
                    {'path': '/items/create', 'method': 'POST'}
                ]
            },
            {
                'name': 'User Deletion',
                'steps': [
                    {'path': '/account/delete', 'method': 'GET'},
                    {'path': '/account/delete', 'method': 'POST'}
                ]
            }
        ]
        
        # Check each workflow
        for workflow in common_workflows:
            valid_steps = []
            
            for step in workflow['steps']:
                url = urllib.parse.urljoin(self.target, step['path'])
                response = make_request(url, method=step['method'])
                
                if response['success'] and response['status_code'] < 404:
                    valid_steps.append({ # type: ignore
                        'path': step['path'],
                        'method': step['method'],
                        'status_code': response['status_code']
                    })
            
            if valid_steps:
                self.workflows.append({
                    'name': workflow['name'],
                    'steps': valid_steps
                })
                logger.info(f"Found workflow: {workflow['name']} with {len(valid_steps)} valid steps")
    
    def _test_authentication_bypasses(self):
        """
        Test for authentication bypass vulnerabilities.
        """
        logger.info("Testing for authentication bypasses")
        
        # Common authentication endpoints
        auth_endpoints = [
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
        
        # Test each authentication endpoint
        for endpoint in auth_endpoints:
            url = urllib.parse.urljoin(self.target, endpoint)
            
            # Test SQL injection in login
            sql_payloads = [
                {'username': "' OR 1=1 --", 'password': 'anything'},
                {'username': "admin' --", 'password': 'anything'},
                {'username': "admin' OR '1'='1", 'password': "' OR '1'='1"},
                {'username': "' OR '1'='1' --", 'password': 'anything'},
                {'username': "' OR 1=1 #", 'password': 'anything'}
            ]
            
            for payload in sql_payloads:
                # Try both form and JSON authentication
                for content_type in ['form', 'json']:
                    if content_type == 'form':
                        response = make_request(url, method='POST', data=payload)
                    else:
                        response = make_request(url, method='POST', json_data=payload)
                    
                    if response.get('success'):
                        # Check if we got past the login page
                        if not self._is_login_page(response['text']) or 'location' in response['headers']:
                            vulnerability = {
                                'url': url,
                                'type': 'Authentication Bypass',
                                'subtype': 'SQL Injection',
                                'method': 'POST',
                                'payload': payload,
                                'content_type': content_type,
                                'description': f"Authentication bypass via SQL injection using {payload}",
                                'severity': 'Critical',
                                'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                            }
                            
                            self.vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential authentication bypass via SQL injection found at {url}")
            
            # Test for default/weak credentials
            default_creds = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'admin', 'password': '123456'},
                {'username': 'admin', 'password': 'admin123'},
                {'username': 'root', 'password': 'root'},
                {'username': 'root', 'password': 'password'},
                {'username': 'user', 'password': 'user'},
                {'username': 'user', 'password': 'password'},
                {'username': 'test', 'password': 'test'},
                {'username': 'guest', 'password': 'guest'}
            ]
            
            for creds in default_creds:
                # Try both form and JSON authentication
                for content_type in ['form', 'json']:
                    if content_type == 'form':
                        response = make_request(url, method='POST', data=creds)
                    else:
                        response = make_request(url, method='POST', json_data=creds)
                    
                    if response.get('success'):
                        # Check if we got past the login page
                        if not self._is_login_page(response['text']) or 'location' in response['headers']:
                            vulnerability = {
                                'url': url,
                                'type': 'Authentication Bypass',
                                'subtype': 'Default/Weak Credentials',
                                'method': 'POST',
                                'payload': creds,
                                'content_type': content_type,
                                'description': f"Authentication bypass via default/weak credentials using {creds}",
                                'severity': 'High',
                                'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                            }
                            
                            self.vulnerabilities.append(vulnerability)
                            logger.warning(f"Potential authentication bypass via default/weak credentials found at {url}")
    
    def _test_parameter_manipulation(self):
        """
        Test for parameter manipulation vulnerabilities.
        """
        logger.info("Testing for parameter manipulation vulnerabilities")
        
        # Common parameters to manipulate
        params_to_test = [
            {'name': 'price', 'values': ['0', '0.01', '-1', '0.00001']},
            {'name': 'quantity', 'values': ['0', '-1', '999999']},
            {'name': 'discount', 'values': ['100', '999', '0.99']},
            {'name': 'total', 'values': ['0', '0.01', '-1']},
            {'name': 'shipping', 'values': ['0', '-1']},
            {'name': 'tax', 'values': ['0', '-1']},
            {'name': 'role', 'values': ['admin', 'administrator', 'superuser']},
            {'name': 'admin', 'values': ['1', 'true', 'yes']},
            {'name': 'debug', 'values': ['1', 'true', 'yes']},
            {'name': 'test', 'values': ['1', 'true', 'yes']},
            {'name': 'bypass', 'values': ['1', 'true', 'yes']},
            {'name': 'skip', 'values': ['1', 'true', 'yes']},
            {'name': 'disable', 'values': ['1', 'true', 'yes']},
            {'name': 'enable', 'values': ['1', 'true', 'yes']}
        ]
        
        # Find forms to test
        forms = self._find_forms()
        
        # Test each form
        for form in forms:
            form_url = form['action']
            form_method = form['method']
            form_inputs = form['inputs']
            
            # For each parameter we want to test
            for param in params_to_test:
                # Check if the form has a similar parameter
                for input_name in form_inputs:
                    if param['name'] in input_name.lower():
                        # Test each value
                        for value in param['values']:
                            # Create form data with the manipulated parameter
                            form_data = {input_name: value}
                            
                            # Add other required fields with dummy values
                            for other_input in form_inputs:
                                if other_input != input_name:
                                    form_data[other_input] = 'test'
                            
                            # Make the request
                            if form_method.upper() == 'GET':
                                test_url = f"{form_url}?{urllib.parse.urlencode(form_data)}"
                                response = make_request(test_url)
                            else:
                                response = make_request(form_url, method=form_method, data=form_data)
                            
                            if response.get('success'):
                                # Check for signs of successful parameter manipulation
                                if self._check_parameter_manipulation_success(response, param['name'], value):
                                    vulnerability = {
                                        'url': form_url,
                                        'type': 'Parameter Manipulation',
                                        'method': form_method,
                                        'parameter': input_name,
                                        'value': value,
                                        'description': f"Parameter manipulation vulnerability with {input_name}={value}",
                                        'severity': 'High',
                                        'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                                    }
                                    
                                    self.vulnerabilities.append(vulnerability)
                                    logger.warning(f"Potential parameter manipulation vulnerability found at {form_url} with {input_name}={value}")
    
    def _test_race_conditions(self):
        """
        Test for race condition vulnerabilities.
        """
        logger.info("Testing for race condition vulnerabilities")
        
        # Common endpoints that might be vulnerable to race conditions
        race_endpoints = [
            '/api/transfer',
            '/api/v1/transfer',
            '/api/v2/transfer',
            '/api/payment',
            '/api/v1/payment',
            '/api/v2/payment',
            '/api/withdraw',
            '/api/v1/withdraw',
            '/api/v2/withdraw',
            '/api/redeem',
            '/api/v1/redeem',
            '/api/v2/redeem',
            '/api/purchase',
            '/api/v1/purchase',
            '/api/v2/purchase',
            '/api/order',
            '/api/v1/order',
            '/api/v2/order',
            '/api/transaction',
            '/api/v1/transaction',
            '/api/v2/transaction'
        ]
        
        # Test each endpoint
        for endpoint in race_endpoints:
            url = urllib.parse.urljoin(self.target, endpoint)
            
            # Create a simple payload
            payload = {
                'amount': '10',
                'to': 'user123',
                'from': 'user456',
                'id': '12345'
            }
            
            # Number of concurrent requests to simulate race condition
            num_requests = 5
            
            # Make concurrent requests
            with ThreadPoolExecutor(max_workers=num_requests) as executor:
                futures = [executor.submit(make_request, url, method='POST', json_data=payload) for _ in range(num_requests)]
                responses = [future.result() for future in futures]
            
            # Check for signs of race condition
            if self._check_race_condition_success(responses):
                vulnerability = {
                    'url': url,
                    'type': 'Race Condition',
                    'method': 'POST',
                    'payload': payload,
                    'description': f"Potential race condition vulnerability with concurrent requests to {endpoint}",
                    'severity': 'High',
                    'evidence': str(responses)[:500]
                }
                
                self.vulnerabilities.append(vulnerability)
                logger.warning(f"Potential race condition vulnerability found at {url}")
    
    def _test_business_constraint_bypasses(self):
        """
        Test for business constraint bypass vulnerabilities.
        """
        logger.info("Testing for business constraint bypass vulnerabilities")
        
        # Find forms to test
        forms = self._find_forms()
        
        # Test each form
        for form in forms:
            form_url = form['action']
            form_method = form['method']
            form_inputs = form['inputs']
            
            # Test for negative values in numeric fields
            for input_name in form_inputs:
                if any(keyword in input_name.lower() for keyword in ['price', 'cost', 'amount', 'total', 'quantity', 'number', 'count']):
                    # Create form data with negative value
                    form_data = {input_name: '-100'}
                    
                    # Add other required fields with dummy values
                    for other_input in form_inputs:
                        if other_input != input_name:
                            form_data[other_input] = 'test'
                    
                    # Make the request
                    if form_method.upper() == 'GET':
                        test_url = f"{form_url}?{urllib.parse.urlencode(form_data)}"
                        response = make_request(test_url)
                    else:
                        response = make_request(form_url, method=form_method, data=form_data)
                    
                    if response.get('success') and response.get('status_code', 0) < 400:
                        vulnerability = {
                            'url': form_url,
                            'type': 'Business Constraint Bypass',
                            'subtype': 'Negative Value',
                            'method': form_method,
                            'parameter': input_name,
                            'value': '-100',
                            'description': f"Business constraint bypass with negative value in {input_name}",
                            'severity': 'High',
                            'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                        }
                        
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Potential business constraint bypass found at {form_url} with {input_name}=-100")
            
            # Test for excessive values in numeric fields
            for input_name in form_inputs:
                if any(keyword in input_name.lower() for keyword in ['price', 'cost', 'amount', 'total', 'quantity', 'number', 'count']):
                    # Create form data with excessive value
                    form_data = {input_name: '999999999'}
                    
                    # Add other required fields with dummy values
                    for other_input in form_inputs:
                        if other_input != input_name:
                            form_data[other_input] = 'test'
                    
                    # Make the request
                    if form_method.upper() == 'GET':
                        test_url = f"{form_url}?{urllib.parse.urlencode(form_data)}"
                        response = make_request(test_url)
                    else:
                        response = make_request(form_url, method=form_method, data=form_data)
                    
                    if response.get('success') and response.get('status_code', 0) < 400:
                        vulnerability = {
                            'url': form_url,
                            'type': 'Business Constraint Bypass',
                            'subtype': 'Excessive Value',
                            'method': form_method,
                            'parameter': input_name,
                            'value': '999999999',
                            'description': f"Business constraint bypass with excessive value in {input_name}",
                            'severity': 'Medium',
                            'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                        }
                        
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Potential business constraint bypass found at {form_url} with {input_name}=999999999")
    
    def _test_workflow_bypasses(self):
        """
        Test for workflow bypass vulnerabilities.
        """
        logger.info("Testing for workflow bypass vulnerabilities")
        
        # Test each discovered workflow
        for workflow in self.workflows:
            # Skip workflows with less than 2 steps
            if len(workflow['steps']) < 2:
                continue
            
            # Try to skip intermediate steps
            first_step = workflow['steps'][0]
            last_step = workflow['steps'][-1]
            
            # Make a request directly to the last step
            last_url = urllib.parse.urljoin(self.target, last_step['path'])
            response = make_request(last_url, method=last_step['method'])
            
            if response.get('success') and response.get('status_code', 0) < 400:
                # Check if the response indicates successful access to the last step
                if not self._is_error_page(response['text']):
                    vulnerability = {
                        'url': last_url,
                        'type': 'Workflow Bypass',
                        'workflow': workflow['name'],
                        'method': last_step['method'],
                        'description': f"Workflow bypass in {workflow['name']} by directly accessing the last step",
                        'severity': 'High',
                        'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                    }
                    
                    self.vulnerabilities.append(vulnerability)
                    logger.warning(f"Potential workflow bypass found in {workflow['name']} at {last_url}")
    
    def _test_insecure_direct_object_references(self):
        """
        Test for insecure direct object reference vulnerabilities.
        """
        logger.info("Testing for insecure direct object references")
        
        # Common patterns for resources that might be vulnerable to IDOR
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
            '/customer/{id}',
            '/orders/{id}',
            '/order/{id}',
            '/invoices/{id}',
            '/invoice/{id}',
            '/items/{id}',
            '/item/{id}',
            '/products/{id}',
            '/product/{id}',
            '/documents/{id}',
            '/document/{id}',
            '/files/{id}',
            '/file/{id}',
            '/api/users/{id}',
            '/api/user/{id}',
            '/api/orders/{id}',
            '/api/order/{id}',
            '/api/items/{id}',
            '/api/item/{id}'
        ]
        
        # Test IDs to try
        test_ids = ['1', '2', '3', '4', '5', '10', '100']
        
        # Test each resource pattern with different IDs
        for pattern in resource_patterns:
            for test_id in test_ids:
                url = urllib.parse.urljoin(self.target, pattern.replace('{id}', test_id))
                response = make_request(url)

                if response.get('success') and response.get('status_code') == 200:
                    # Check if the response contains sensitive data
                    if self._contains_sensitive_data(response['text']):
                        vulnerability = {
                            'url': url,
                            'type': 'Insecure Direct Object Reference',
                            'resource': pattern,
                            'id': test_id,
                            'description': f"IDOR vulnerability in {pattern} with ID {test_id}",
                            'severity': 'High',
                            'evidence': response['text'][:500] if len(response['text']) > 500 else response['text']
                        }
                        
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(f"Potential IDOR vulnerability found at {url}")
    
    def _find_forms(self):
        """
        Find forms in the application.
        
        Returns:
            list: List of forms with their action, method, and inputs
        """
        forms = []
        
        # Make a request to the target
        response = make_request(self.target) # type: ignore
        
        if response['success']:
            # Parse the HTML
            soup = BeautifulSoup(response['text'], 'html.parser')
            
            # Find all forms
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                
                # If the action is relative, make it absolute
                if form_action and not form_action.startswith(('http://', 'https://')):
                    form_action = urllib.parse.urljoin(self.target, form_action)
                elif not form_action:
                    form_action = self.target
                
                # Find all input fields
                inputs = []
                for input_field in form.find_all('input'):
                    input_name = input_field.get('name')
                    if input_name and input_field.get('type') != 'submit':
                        inputs.append(input_name)
                
                forms.append({
                    'action': form_action,
                    'method': form_method,
                    'inputs': inputs
                })
        
        return forms
    
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
    
    def _is_error_page(self, html_content):
        """
        Check if the page is an error page.
        
        Args:
            html_content (str): HTML content of the page
            
        Returns:
            bool: True if it's an error page, False otherwise
        """
        # Look for common error page indicators
        error_indicators = [
            r'error',
            r'not found',
            r'404',
            r'403',
            r'forbidden',
            r'unauthorized',
            r'access denied',
            r'permission denied',
            r'not authorized',
            r'bad request',
            r'invalid',
            r'exception',
            r'server error',
            r'internal server error',
            r'500'
        ]
        
        html_lower = html_content.lower()
        
        for indicator in error_indicators:
            if re.search(r'\b' + indicator + r'\b', html_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _check_parameter_manipulation_success(self, response, param_name, value):
        """
        Check if parameter manipulation was successful.
        
        Args:
            response (dict): Response from the request
            param_name (str): Name of the parameter
            value (str): Value used for the parameter
            
        Returns:
            bool: True if manipulation was successful, False otherwise
        """
        # Check for success indicators based on the parameter and value
        if param_name == 'price' and value in ['0', '0.01', '-1', '0.00001']:
            # Look for success indicators in the response
            success_indicators = [
                r'order\s*confirmed',
                r'purchase\s*successful',
                r'thank\s*you\s*for\s*your\s*order',
                r'order\s*placed',
                r'payment\s*successful',
                r'transaction\s*complete'
            ]
            
            for indicator in success_indicators:
                if re.search(indicator, response['text'], re.IGNORECASE):
                    return True
        
        elif param_name == 'role' and value in ['admin', 'administrator', 'superuser']:
            # Look for admin panel indicators
            admin_indicators = [
                r'admin\s*panel',
                r'dashboard',
                r'control\s*panel',
                r'manage\s*users',
                r'site\s*settings',
                r'configuration'
            ]
            
            for indicator in admin_indicators:
                if re.search(indicator, response.get('text', ''), re.IGNORECASE):
                    return True
        
        # Generic check for non-error response
        return response.get('status_code', 0) < 400 and not self._is_error_page(response.get('text', ''))
    
    def _check_race_condition_success(self, responses):
        """ # type: ignore
        Check if race condition testing was successful.
        
        Args:
            responses (list): List of responses from concurrent requests
            
        Returns:
            bool: True if race condition was detected, False otherwise
        """
        # Check for inconsistent responses
        status_codes = set(response.get('status_code', 0) for response in responses if response.get('success'))
        
        # If we got different status codes, it might indicate a race condition
        if len(status_codes) > 1:
            return True
        
        # Check for duplicate transaction IDs or other indicators in JSON responses
        json_responses = []
        for response in responses: # type: ignore
            if response['success'] and 'text' in response:
                try:
                    json_data = json.loads(response['text'])
                    json_responses.append(json_data)
                except json.JSONDecodeError:
                    pass
        
        # If we have JSON responses, check for duplicate IDs
        if json_responses:
            transaction_ids = []
            for json_data in json_responses:
                if isinstance(json_data, dict):
                    for key in ['id', 'transaction_id', 'order_id', 'reference']:
                        if key in json_data:
                            transaction_ids.append(json_data[key])
            
            # If we have duplicate IDs, it might indicate a race condition
            if len(transaction_ids) != len(set(transaction_ids)):
                return True
        
        return False
    
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