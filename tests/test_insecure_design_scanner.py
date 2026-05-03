#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the Insecure Design Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.vuln_testing.insecure_design_scanner import InsecureDesignScanner


class TestInsecureDesignScanner(unittest.TestCase):
    """Test cases for the Insecure Design Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = InsecureDesignScanner()
        self.test_config = {
            'target': 'http://example.com'
        }

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "Insecure Design Scanner")
        self.assertEqual(self.scanner.category, "vuln_testing")
        self.assertIsInstance(self.scanner.insecure_patterns, dict)
        self.assertIn("predictable_ids", self.scanner.insecure_patterns)
        self.assertIn("debug_info", self.scanner.insecure_patterns)
        self.assertIn("insecure_direct_object_reference", self.scanner.insecure_patterns)

    @patch('modules.vuln_testing.insecure_design_scanner.make_request')
    def test_analyze_target(self, mock_make_request):
        """Test analyzing a target for insecure design patterns."""
        # Mock response with insecure patterns
        mock_response = MagicMock()
        mock_response.text = """
        mock_response.text = """ # type: ignore
        <html>
            <body>
                <a href="/user?id=123">User Profile</a>
                <div class="error">Exception in thread "main" java.lang.NullPointerException at com.example.Main.process(Main.java:123)</div>
                <form action="/load?file=document.pdf" method="get">
                    <input type="hidden" name="api_key" value="abc123xyz">
                </form>
            </body>
        </html>
        """
        mock_response.status_code = 200
        """ # type: ignore
        mock_response.status_code = 200 # type: ignore
        mock_response.headers = {
            'Server': 'Apache/2.4.41',
            'X-Powered-By': 'PHP/7.4.3'
        }
        } # type: ignore
        mock_make_request.return_value = mock_response
        
        # Run the analysis
        self.scanner.config = self.test_config
        results = self.scanner.run()
        
        # Check that vulnerabilities were found
        self.assertGreater(len(results.get('vulnerabilities', [])), 0)
        
        # Check for specific vulnerability types
        vuln_types = [v.get('type') for v in results.get('vulnerabilities', [])]
        self.assertTrue(any('Insecure Design' in vt for vt in vuln_types))

    @patch('modules.vuln_testing.insecure_design_scanner.make_request')
    def test_check_authentication_design(self, mock_make_request):
        """Test checking authentication design issues."""
        # Mock login page response
        mock_login_response = MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.headers = {}
        mock_login_response.text = '<form action="/login" method="post">Login Form</form>'
        mock_login_response = MagicMock() # type: ignore
        mock_login_response.status_code = 200 # type: ignore
        mock_login_response.headers = {} # type: ignore
        mock_login_response.text = '<form action="/login" method="post">Login Form</form>' # type: ignore
        
        # Mock password reset page response
        mock_reset_response = MagicMock()
        mock_reset_response.status_code = 200
        mock_reset_response.headers = {}
        mock_reset_response.text = '<form action="/reset" method="post">Reset Form</form>'
        mock_reset_response = MagicMock() # type: ignore
        mock_reset_response.status_code = 200 # type: ignore
        mock_reset_response.headers = {} # type: ignore
        mock_reset_response.text = '<form action="/reset" method="post">Reset Form</form>' # type: ignore
        
        # Configure mock to return different responses based on URL
        def side_effect(url, **kwargs):
            if '/login' in url:
                return mock_login_response
            elif '/reset' in url or '/forgot' in url:
                return mock_reset_response
            return MagicMock(status_code=404, text="")
        
        mock_make_request.side_effect = side_effect
        
        # Run the check
        results = {'vulnerabilities': []}
        self.scanner._check_authentication_design('http://example.com', results)
        
        # Check that vulnerabilities were found
        self.assertGreater(len(results['vulnerabilities']), 0)
        
        # Check for specific vulnerability types
        auth_vulns = [v for v in results['vulnerabilities'] if v['type'] == 'Insecure Design - Authentication']
        self.assertGreater(len(auth_vulns), 0)

    @patch('modules.vuln_testing.insecure_design_scanner.make_request')
    def test_check_authorization_design(self, mock_make_request):
        """Test checking authorization design issues."""
        # Mock admin page response - accessible without auth
        mock_admin_response = MagicMock()
        mock_admin_response.status_code = 200
        mock_admin_response.headers = {}
        mock_admin_response.text = '<h1>Admin Dashboard</h1>'
        mock_admin_response = MagicMock() # type: ignore
        mock_admin_response.status_code = 200 # type: ignore
        mock_admin_response.headers = {} # type: ignore
        mock_admin_response.text = '<h1>Admin Dashboard</h1>' # type: ignore
        
        # Mock dashboard page response - redirects to login
        mock_dashboard_response = MagicMock()
        mock_dashboard_response.status_code = 302
        mock_dashboard_response.headers = {'Location': '/login'}
        mock_dashboard_response.text = ''
        mock_dashboard_response = MagicMock() # type: ignore
        mock_dashboard_response.status_code = 302 # type: ignore
        mock_dashboard_response.headers = {'Location': '/login'} # type: ignore
        mock_dashboard_response.text = '' # type: ignore
        
        # Configure mock to return different responses based on URL
        def side_effect(url):
            if '/admin' in url:
                return mock_admin_response
            elif '/dashboard' in url:
                return mock_dashboard_response
            return None
        
        mock_make_request.side_effect = side_effect
        
        # Run the check
        results = {'vulnerabilities': []}
        self.scanner.check_authorization_design('http://example.com', results)
        
        # Check that vulnerabilities were found
        self.assertGreater(len(results['vulnerabilities']), 0)
        
        # Check for specific vulnerability types
        auth_vulns = [v for v in results['vulnerabilities'] if v['type'] == 'Insecure Design - Authorization']
        self.assertGreater(len(auth_vulns), 0)
        
        # Check for high severity vulnerability (admin page accessible)
        high_vulns = [v for v in auth_vulns if v['severity'] == 'High']
        self.assertGreater(len(high_vulns), 0)

    @patch('modules.vuln_testing.insecure_design_scanner.make_request')
    def test_check_business_logic(self, mock_make_request):
        """Test checking business logic design issues."""
        # Mock checkout page response with price parameters
        mock_checkout_response = MagicMock()
        mock_checkout_response = MagicMock() # type: ignore
        mock_checkout_response.status_code = 200
        mock_checkout_response.headers = {}
        mock_checkout_response.text = '''
        <form action="/process-order" method="post">
            <input type="hidden" name="price" value="99.99">
            <input type="hidden" name="quantity" value="2">
            <input type="hidden" name="total" value="199.98">
        </form>
        '''
        
        # Configure mock
        def side_effect(url):
            if '/checkout' in url or '/cart' in url:
                return mock_checkout_response
            return None
        
        mock_make_request.side_effect = side_effect
        
        # Run the check
        results = {'vulnerabilities': []}
        self.scanner.check_business_logic('http://example.com', results)
        
        # Check that vulnerabilities were found
        self.assertGreater(len(results['vulnerabilities']), 0)
        
        # Check for specific vulnerability types
        business_vulns = [v for v in results['vulnerabilities'] if v['type'] == 'Insecure Design - Business Logic']
        self.assertGreater(len(business_vulns), 0)

    @patch('modules.vuln_testing.insecure_design_scanner.make_request')
    def test_check_api_design(self, mock_make_request):
        """Test checking API design issues."""
        # Mock API response with documentation
        mock_api_response = MagicMock()
        mock_api_response = MagicMock() # type: ignore
        mock_api_response.status_code = 200
        mock_api_response.headers = {'Content-Type': 'application/json'}
        mock_api_response.text = '''
        {
            "swagger": "2.0",
            "info": {
                "title": "Example API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get all users"
                    }
                }
            }
        }
        '''
        
        # Configure mock
        def side_effect(url):
            if '/api' in url:
                return mock_api_response
            return None
        
        mock_make_request.side_effect = side_effect
        
        # Run the check
        results = {'vulnerabilities': []}
        self.scanner.check_api_design('http://example.com', results)
        
        # Check that vulnerabilities were found
        self.assertGreater(len(results['vulnerabilities']), 0)
        
        # Check for specific vulnerability types
        api_vulns = [v for v in results['vulnerabilities'] if v['type'] == 'Insecure Design - API']
        self.assertGreater(len(api_vulns), 0)

    def test_extract_links(self):
        """Test extracting links from HTML content."""
        # Create mock response with links
        mock_response = MagicMock()
        mock_response = MagicMock() # type: ignore
        mock_response.text = '''
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
                <img src="/images/logo.png">
                <form action="/submit" method="post">
                    <input type="submit" value="Submit">
                </form>
            </body>
        </html>
        '''
        
        # Extract links
        links = self.scanner.extract_links(mock_response)
        
        # Check that links were extracted
        self.assertIn('/page1', links)
        self.assertIn('https://example.com/page2', links)
        self.assertIn('/images/logo.png', links)
        self.assertIn('/submit', links)

    def test_should_analyze_link(self):
        """Test link analysis filtering."""
        base_url = 'http://example.com'
        
        # Links that should be analyzed
        self.assertTrue(self.scanner.should_analyze_link(base_url, '/page1'))
        self.assertTrue(self.scanner.should_analyze_link(base_url, 'http://example.com/page2'))
        self.assertTrue(self.scanner.should_analyze_link(base_url, '/api/users'))
        
        # Links that should not be analyzed
        self.assertFalse(self.scanner.should_analyze_link(base_url, 'http://external-site.com/page'))
        self.assertFalse(self.scanner.should_analyze_link(base_url, 'mailto:info@example.com'))
        self.assertFalse(self.scanner.should_analyze_link(base_url, '#section1'))
        self.assertFalse(self.scanner.should_analyze_link(base_url, '/styles.css'))
        self.assertFalse(self.scanner.should_analyze_link(base_url, '/script.js'))
        self.assertFalse(self.scanner.should_analyze_link(base_url, '/image.png'))

    def test_join_url(self):
        """Test URL joining functionality."""
        # Test various combinations
        self.assertEqual(self.scanner.join_url('http://example.com', '/page'), 'http://example.com/page')
        self.assertEqual(self.scanner.join_url('http://example.com/', '/page'), 'http://example.com/page')
        self.assertEqual(self.scanner.join_url('http://example.com', 'page'), 'http://example.com/page')
        self.assertEqual(self.scanner.join_url('http://example.com/', 'page'), 'http://example.com/page')

    def test_add_vulnerability(self):
        """Test adding vulnerabilities to results."""
        results = {'vulnerabilities': []}
        
        # Add a vulnerability
        vuln1 = {
            'type': 'Insecure Design - Test',
            'url': 'http://example.com/test',
            'evidence': 'Test evidence',
            'description': 'Test description',
            'severity': 'Medium'
        }
        self.scanner.add_vulnerability(results, vuln1)
        
        # Check that it was added
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'Insecure Design - Test')
        self.assertEqual(results['vulnerabilities'][0]['url'], 'http://example.com/test')
        
        # Add a duplicate vulnerability
        vuln2 = vuln1.copy()
        self.scanner.add_vulnerability(results, vuln2)
        
        # Check that duplicate was not added
        self.assertEqual(len(results['vulnerabilities']), 1)
        
        # Add a different vulnerability
        vuln3 = {
            'type': 'Insecure Design - Test',
            'url': 'http://example.com/different',
            'evidence': 'Different evidence',
            'description': 'Different description',
            'severity': 'High'
        }
        self.scanner.add_vulnerability(results, vuln3)
        
        # Check that different vulnerability was added
        self.assertEqual(len(results['vulnerabilities']), 2)


if __name__ == '__main__':
    unittest.main()