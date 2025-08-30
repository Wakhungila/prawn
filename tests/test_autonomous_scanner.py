#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test cases for the Autonomous Scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock
import threading
import time

from modules.autonomous.autonomous_scanner import AutonomousScanner


class TestAutonomousScanner(unittest.TestCase):
    """Test cases for the Autonomous Scanner module."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = AutonomousScanner()
        self.test_config = {
            'targets': ['http://example.com'],
            'max_concurrent_scans': 2,
            'discover_targets': True,
            'discovery_methods': ['dns'],
            'output_dir': 'test_results'
        }

    def test_initialization(self):
        """Test that the scanner initializes correctly."""
        self.assertEqual(self.scanner.name, "Autonomous Scanner")
        self.assertEqual(self.scanner.category, "autonomous")
        self.assertIsInstance(self.scanner.discovered_targets, set)
        self.assertIsInstance(self.scanner.scanned_targets, set)
        self.assertIsInstance(self.scanner.scan_queue, list)
        self.assertIsInstance(self.scanner.active_scans, dict)
        self.assertIsInstance(self.scanner.scan_results, dict)
        self.assertIsInstance(self.scanner.stop_event, threading.Event)

    def test_add_target(self):
        """Test adding targets to the scan queue."""
        # Test adding a target without http prefix
        self.scanner.add_target('example.com')
        self.assertIn('http://example.com', self.scanner.discovered_targets)
        self.assertIn('http://example.com', self.scanner.scan_queue)
        
        # Test adding a target with http prefix
        self.scanner.add_target('http://test.com')
        self.assertIn('http://test.com', self.scanner.discovered_targets)
        self.assertIn('http://test.com', self.scanner.scan_queue)
        
        # Test adding a duplicate target
        initial_queue_length = len(self.scanner.scan_queue)
        self.scanner.add_target('http://test.com')
        self.assertEqual(len(self.scanner.scan_queue), initial_queue_length)
        
        # Test adding a target that's already been scanned
        self.scanner.scanned_targets.add('http://scanned.com')
        self.scanner.add_target('http://scanned.com')
        self.assertNotIn('http://scanned.com', self.scanner.scan_queue)

    @patch('modules.autonomous.autonomous_scanner.AutonomousScanner.discover_targets_dns')
    def test_discover_targets(self, mock_discover_dns):
        """Test target discovery functionality."""
        self.scanner.discover_targets(self.test_config)
        mock_discover_dns.assert_called_once_with(self.test_config)

    @patch('modules.autonomous.autonomous_scanner.AutonomousScanner.scan_target')
    def test_run_with_initial_targets(self, mock_scan_target):
        """Test running the scanner with initial targets."""
        # Setup mock for scan_target
        def side_effect(target, scan_id, config):
            time.sleep(0.1)  # Simulate some work
            return {'status': 'completed'}
        
        mock_scan_target.side_effect = side_effect
        
        # Run the scanner with a timeout
        self.scanner.stop_event = threading.Event()
        
        # Start the scanner in a separate thread
        scanner_thread = threading.Thread(
            target=self.scanner.run,
            args=(self.test_config,)
        )
        scanner_thread.daemon = True
        scanner_thread.start()
        
        # Let it run for a short time
        time.sleep(0.5)
        
        # Stop the scanner
        self.scanner.stop()
        scanner_thread.join(timeout=1)
        
        # Verify the scanner processed the initial target
        self.assertGreaterEqual(mock_scan_target.call_count, 1)
        mock_scan_target.assert_any_call(
            'http://example.com', 
            unittest.mock.ANY,  # scan_id is dynamically generated
            self.test_config
        )

    def test_process_scan_result(self):
        """Test processing scan results for new targets."""
        # Create a mock scan result
        result = {
            'links': [
                'http://example.com/page1',
                'http://subdomain.example.com',
                'http://external-site.com'
            ],
            'subdomains': ['api.example.com', 'admin.example.com'],
            'ip_addresses': ['192.168.1.1', '10.0.0.1']
        }
        
        # Process the result
        self.scanner.process_scan_result(result, 'http://example.com')
        
        # Check that appropriate targets were added
        self.assertIn('http://example.com/page1', self.scanner.discovered_targets)
        self.assertIn('http://subdomain.example.com', self.scanner.discovered_targets)
        self.assertIn('http://api.example.com', self.scanner.discovered_targets)
        self.assertIn('http://admin.example.com', self.scanner.discovered_targets)
        self.assertIn('http://192.168.1.1', self.scanner.discovered_targets)
        self.assertIn('http://10.0.0.1', self.scanner.discovered_targets)
        
        # External site should also be added as it might be related
        self.assertIn('http://external-site.com', self.scanner.discovered_targets)

    def test_stop(self):
        """Test stopping the scanner."""
        self.scanner.stop_event.clear()
        self.assertFalse(self.scanner.stop_event.is_set())
        
        self.scanner.stop()
        self.assertTrue(self.scanner.stop_event.is_set())


if __name__ == '__main__':
    unittest.main()