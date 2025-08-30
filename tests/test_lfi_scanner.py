#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the Local File Inclusion (LFI) Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.vuln_testing.lfi_scanner import LFIScanner


class TestLFIScanner(unittest.TestCase):
    """Test cases for the Local File Inclusion (LFI) Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = LFIScanner()
        self.test_config = {
            'target': 'http://example.com'
        }

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "Local File Inclusion Scanner")
        self.assertEqual(self.scanner.category, "vuln_testing")
        self.assertIsInstance(self.scanner.payloads, list)
        self.assertTrue(len(self.scanner.payloads) > 0)

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_detect_lfi_unix(self, mock_make_request):
        """Test detection of LFI vulnerability on Unix-like systems."""
        # Mock response with LFI vulnerability
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=../../../etc/passwd'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'Local File Inclusion')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'High')
        self.assertIn('etc/passwd', results['vulnerabilities'][0]['evidence'])

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_detect_lfi_windows(self, mock_make_request):
        """Test detection of LFI vulnerability on Windows systems."""
        # Mock response with LFI vulnerability
        mock_response = MagicMock()
        mock_response.text = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=..\\..\\..\\boot.ini'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'Local File Inclusion')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'High')
        self.assertIn('boot loader', results['vulnerabilities'][0]['evidence'])

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_detect_lfi_php_filter(self, mock_make_request):
        """Test detection of LFI vulnerability using PHP filter."""
        # Mock response with LFI vulnerability using PHP filter
        mock_response = MagicMock()
        # Base64 encoded "<?php phpinfo(); ?>"
        mock_response.text = "PD9waHAgcGhwaW5mbygpOyA/Pg=="
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=php://filter/convert.base64-encode/resource=config'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'Local File Inclusion')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'High')
        self.assertIn('php filter', results['vulnerabilities'][0]['description'].lower())

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_detect_lfi_null_byte(self, mock_make_request):
        """Test detection of LFI vulnerability with null byte injection."""
        # Mock response with LFI vulnerability
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=../../../etc/passwd%00'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'Local File Inclusion')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'High')
        self.assertIn('null byte', results['vulnerabilities'][0]['description'].lower())

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_no_lfi_vulnerability(self, mock_make_request):
        """Test that no vulnerability is reported when LFI is not present."""
        # Mock response without LFI vulnerability
        mock_response = MagicMock()
        mock_response.text = "<html><body>Normal page content</body></html>"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=safe_file'
        self.scanner.scan(target_url, results)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 0)

    @patch('modules.vuln_testing.lfi_scanner.make_request')
    def test_error_response(self, mock_make_request):
        """Test handling of error responses during scanning."""
        # Mock error response
        mock_response = MagicMock()
        mock_response.text = "<html><body>Error: File not found</body></html>"
        mock_response.status_code = 404
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/page.php?file=../../../etc/passwd'
        self.scanner.scan(target_url, results)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 0)

    def test_extract_parameters(self):
        """Test extraction of parameters from URLs."""
        # Test URL with query parameters
        url = 'http://example.com/page.php?file=image.jpg&id=123&action=view'
        params = self.scanner.extract_parameters(url)
        self.assertEqual(len(params), 3)
        self.assertIn('file', params)
        self.assertIn('id', params)
        self.assertIn('action', params)
        self.assertEqual(params['file'], 'image.jpg')
        self.assertEqual(params['id'], '123')
        self.assertEqual(params['action'], 'view')
        
        # Test URL without query parameters
        url = 'http://example.com/page.php'
        params = self.scanner.extract_parameters(url)
        self.assertEqual(len(params), 0)

    def test_generate_lfi_payloads(self):
        """Test generation of LFI payloads."""
        payloads = self.scanner.generate_lfi_payloads()
        self.assertTrue(len(payloads) > 0)
        
        # Check for common LFI patterns
        payload_strings = [str(p) for p in payloads]
        self.assertTrue(any('../' in p for p in payload_strings))
        self.assertTrue(any('etc/passwd' in p for p in payload_strings))
        self.assertTrue(any('php://' in p for p in payload_strings))

    def test_is_file_parameter(self):
        """Test detection of file-related parameters."""
        # File-related parameters
        self.assertTrue(self.scanner.is_file_parameter('file'))
        self.assertTrue(self.scanner.is_file_parameter('document'))
        self.assertTrue(self.scanner.is_file_parameter('include'))
        self.assertTrue(self.scanner.is_file_parameter('path'))
        
        # Non-file-related parameters
        self.assertFalse(self.scanner.is_file_parameter('id'))
        self.assertFalse(self.scanner.is_file_parameter('action'))
        self.assertFalse(self.scanner.is_file_parameter('user'))


if __name__ == '__main__':
    unittest.main()