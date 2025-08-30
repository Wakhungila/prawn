#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the XXE Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock

from modules.vuln_testing.xxe_scanner import XXEScanner


class TestXXEScanner(unittest.TestCase):
    """Test cases for the XXE Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = XXEScanner()
        self.test_config = {
            'target': 'http://example.com'
        }

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "XXE Scanner")
        self.assertEqual(self.scanner.category, "vuln_testing")
        self.assertIsInstance(self.scanner.payloads, list)
        self.assertTrue(len(self.scanner.payloads) > 0)

    @patch('modules.vuln_testing.xxe_scanner.make_request')
    def test_detect_xxe_file_disclosure(self, mock_make_request):
        """Test detection of XXE vulnerability with file disclosure."""
        # Mock response with XXE vulnerability
        mock_response = MagicMock()
        mock_response.text = "Response contains root:x:0:0:root:/root:/bin/bash from /etc/passwd"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/api/process-xml'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'XML External Entity (XXE)')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'Critical')
        self.assertIn('/etc/passwd', results['vulnerabilities'][0]['evidence'])

    @patch('modules.vuln_testing.xxe_scanner.make_request')
    def test_detect_xxe_ssrf(self, mock_make_request):
        """Test detection of XXE vulnerability with SSRF."""
        # Mock response with XXE+SSRF vulnerability
        mock_response = MagicMock()
        mock_response.text = "Response contains data from internal service: {\"status\":\"up\",\"version\":\"1.2.3\"}"
        mock_response.status_code = 200
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/api/process-xml'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'XML External Entity (XXE)')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'Critical')
        self.assertIn('SSRF', results['vulnerabilities'][0]['description'])

    @patch('modules.vuln_testing.xxe_scanner.make_request')
    def test_detect_xxe_blind(self, mock_make_request):
        """Test detection of blind XXE vulnerability."""
        # Mock responses for blind XXE detection
        def side_effect(url, data=None, headers=None, method=None):
            response = MagicMock()
            # Simulate delayed response for blind XXE detection
            if data and '<!ENTITY' in data and 'SYSTEM' in data and 'sleep' in data:
                response.elapsed.total_seconds.return_value = 10.5  # Simulated delay
                response.text = "Normal response"
                response.status_code = 200
            else:
                response.elapsed.total_seconds.return_value = 0.1  # Normal response time
                response.text = "Normal response"
                response.status_code = 200
            return response
        
        mock_make_request.side_effect = side_effect
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/api/process-xml'
        self.scanner.scan(target_url, results)
        
        # Check that vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 1)
        self.assertEqual(results['vulnerabilities'][0]['type'], 'XML External Entity (XXE)')
        self.assertEqual(results['vulnerabilities'][0]['severity'], 'High')
        self.assertIn('blind', results['vulnerabilities'][0]['description'].lower())

    @patch('modules.vuln_testing.xxe_scanner.make_request')
    def test_no_xxe_vulnerability(self, mock_make_request):
        """Test that no vulnerability is reported when XXE is not present."""
        # Mock response without XXE vulnerability
        mock_response = MagicMock()
        mock_response.text = "<result>Normal XML processing result</result>"
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 0.1  # Normal response time
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/api/process-xml'
        self.scanner.scan(target_url, results)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 0)

    @patch('modules.vuln_testing.xxe_scanner.make_request')
    def test_error_response(self, mock_make_request):
        """Test handling of error responses during scanning."""
        # Mock error response
        mock_response = MagicMock()
        mock_response.text = "<error>Invalid XML format</error>"
        mock_response.status_code = 400
        mock_make_request.return_value = mock_response
        
        # Run the scan
        results = {'vulnerabilities': []}
        target_url = 'http://example.com/api/process-xml'
        self.scanner.scan(target_url, results)
        
        # Check that no vulnerability was detected
        self.assertEqual(len(results['vulnerabilities']), 0)

    def test_generate_xxe_payloads(self):
        """Test generation of XXE payloads."""
        payloads = self.scanner.generate_xxe_payloads()
        self.assertTrue(len(payloads) > 0)
        
        # Check for common XXE patterns
        payload_strings = [str(p) for p in payloads]
        self.assertTrue(any('<!ENTITY' in p for p in payload_strings))
        self.assertTrue(any('SYSTEM' in p for p in payload_strings))
        self.assertTrue(any('file:///' in p for p in payload_strings))

    def test_is_xml_endpoint(self):
        """Test detection of XML endpoints."""
        # XML endpoints
        self.assertTrue(self.scanner.is_xml_endpoint('http://example.com/api/process-xml'))
        self.assertTrue(self.scanner.is_xml_endpoint('http://example.com/soap'))
        self.assertTrue(self.scanner.is_xml_endpoint('http://example.com/api/data', {'Content-Type': 'application/xml'}))
        self.assertTrue(self.scanner.is_xml_endpoint('http://example.com/api/data', {'Content-Type': 'text/xml'}))
        
        # Non-XML endpoints
        self.assertFalse(self.scanner.is_xml_endpoint('http://example.com/api/json'))
        self.assertFalse(self.scanner.is_xml_endpoint('http://example.com/api/data', {'Content-Type': 'application/json'}))
        self.assertFalse(self.scanner.is_xml_endpoint('http://example.com/api/data', {'Content-Type': 'text/html'}))

    def test_detect_xml_patterns(self):
        """Test detection of XML patterns in responses."""
        # XML patterns
        self.assertTrue(self.scanner.detect_xml_patterns('<xml version="1.0">Test</xml>'))
        self.assertTrue(self.scanner.detect_xml_patterns('Response with <tag>XML content</tag>'))
        self.assertTrue(self.scanner.detect_xml_patterns('<?xml version="1.0" encoding="UTF-8"?>'))
        
        # Non-XML patterns
        self.assertFalse(self.scanner.detect_xml_patterns('{"json": "content"}'))
        self.assertFalse(self.scanner.detect_xml_patterns('Plain text response'))
        self.assertFalse(self.scanner.detect_xml_patterns('<html><body>HTML content</body></html>'))


if __name__ == '__main__':
    unittest.main()