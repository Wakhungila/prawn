#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Autonomous Scanner Module for PIN0CCHI0

This module provides autonomous scanning capabilities, allowing PIN0CCHI0
to automatically discover and test targets without manual intervention.
"""

import os
import json
import time
import asyncio
import logging
import threading
from urllib.parse import urlparse

from core.base_module import BaseModule
from core.utils import make_request, run_command

from core.engine import PrawnOrchestrator
from core.schemas import ScanConfig as PrawnScanConfig
# Configure logger
logger = logging.getLogger('pin0cchi0.autonomous.scanner')

class AutonomousScanner(BaseModule):
    """Autonomous Scanner module for PIN0CCHI0."""
    
    def __init__(self):
        """Initialize the Autonomous Scanner module."""
        super().__init__()
        self.name = "Autonomous Scanner"
        self.description = "Provides autonomous scanning capabilities"
        self.category = "autonomous"
        self.author = "PIN0CCHI0 Team"
        self.version = "0.1.0"
        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/"
        ]
        
        # Initialize state
        self.discovered_targets = set()
        self.scanned_targets = set()
        self.scan_queue = []
        self.active_scans = {}
        self.scan_results = {}
        self.stop_event = threading.Event()
        
    def run(self, config=None):
        """Run the autonomous scanner."""
        if config is None:
            config = self.config
        
        # Get initial targets
        initial_targets = config.get('targets', [])
        if isinstance(initial_targets, str):
            initial_targets = [initial_targets]
        
        # Add initial targets to queue
        for target in initial_targets:
            self.add_target(target)
        
        # If no initial targets, try to discover targets
        if not self.scan_queue and config.get('discover_targets', False):
            self.discover_targets(config)
        
        # Start scanning
        max_concurrent_scans = config.get('max_concurrent_scans', 3)
        scan_threads = []
        
        try:
            while self.scan_queue or self.active_scans:
                # Check if we should stop
                if self.stop_event.is_set():
                    logger.info("Stopping autonomous scanner")
                    break
                
                # Start new scans if we have capacity
                while len(self.active_scans) < max_concurrent_scans and self.scan_queue:
                    target = self.scan_queue.pop(0)
                    if target in self.scanned_targets:
                        continue
                    
                    # Create a thread for this scan
                    scan_id = f"{int(time.time())}-{target.replace('://', '-').replace('/', '-')}"
                    thread = threading.Thread(
                        target=self.scan_target,
                        args=(target, scan_id, config)
                    )
                    thread.daemon = True
                    thread.start()
                    
                    # Track the scan
                    self.active_scans[scan_id] = {
                        'target': target,
                        'thread': thread,
                        'start_time': time.time()
                    }
                    scan_threads.append(thread)
                    
                    logger.info(f"Started scan {scan_id} for {target}")
                
                # Check for completed scans
                completed_scans = []
                for scan_id, scan_info in self.active_scans.items():
                    if not scan_info['thread'].is_alive():
                        completed_scans.append(scan_id)
                        self.scanned_targets.add(scan_info['target'])
                        logger.info(f"Scan {scan_id} for {scan_info['target']} completed")
                
                # Remove completed scans
                for scan_id in completed_scans:
                    del self.active_scans[scan_id]
                
                # Sleep a bit to avoid high CPU usage
                time.sleep(1)
            
            # Wait for all scan threads to complete
            for thread in scan_threads:
                if thread.is_alive():
                    thread.join(timeout=5)
            
            return {
                'discovered_targets': list(self.discovered_targets),
                'scanned_targets': list(self.scanned_targets),
                'scan_results': self.scan_results
            }
            
        except KeyboardInterrupt:
            logger.warning("Autonomous scanner interrupted by user")
            self.stop_event.set()
            return {
                'status': 'interrupted',
                'discovered_targets': list(self.discovered_targets),
                'scanned_targets': list(self.scanned_targets),
                'scan_results': self.scan_results
            }
    
    def add_target(self, target):
        """Add a target to the scan queue."""
        # Normalize target URL
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Add to discovered targets and scan queue
        self.discovered_targets.add(target)
        if target not in self.scanned_targets and target not in [t for t in self.scan_queue]:
            self.scan_queue.append(target)
            logger.info(f"Added target to scan queue: {target}")
    
    def discover_targets(self, config):
        """Discover potential targets."""
        logger.info("Discovering potential targets")
        
        # Methods for target discovery
        discovery_methods = config.get('discovery_methods', ['dns', 'whois', 'shodan'])
        
        # DNS discovery
        if 'dns' in discovery_methods:
            self.discover_targets_dns(config)
        
        # WHOIS discovery
        if 'whois' in discovery_methods:
            self.discover_targets_whois(config)
        
        # Shodan discovery
        if 'shodan' in discovery_methods:
            self.discover_targets_shodan(config)
        
        logger.info(f"Discovered {len(self.discovered_targets)} potential targets")
    
    def discover_targets_dns(self, config):
        """Discover targets using DNS techniques."""
        # Implementation would use DNS zone transfers, subdomain enumeration, etc.
        pass
    
    def discover_targets_whois(self, config):
        """Discover targets using WHOIS information."""
        # Implementation would parse WHOIS data for related domains
        pass
    
    def discover_targets_shodan(self, config):
        """Discover targets using Shodan API."""
        # Implementation would use Shodan API to find related targets
        pass
    
    def scan_target(self, target, scan_id, config):
        """Scan a specific target."""
        logger.info(f"Scanning target: {target}")
        
        try:
            # Create scan configuration
            scan_config = config.copy()
            scan_config['target'] = target
            scan_config['output_dir'] = os.path.join(
                config.get('output_dir', 'results'),
                scan_id
            )
            
            # Create output directory
            os.makedirs(scan_config['output_dir'], exist_ok=True)
            
            # Run the scan using the engine
            from core.engine import Engine
            from core.config_manager import ConfigManager
            from core.module_manager import ModuleManager
            
            config_manager = ConfigManager()
            config_manager.config.update(scan_config)
            
            module_manager = ModuleManager(config_manager)
            
            # Exclude this module to avoid recursion
            exclude_modules = scan_config.get('exclude_modules', [])
            exclude_modules.append('autonomous_scanner')
            scan_config['exclude_modules'] = exclude_modules
            
            engine = Engine(config_manager, module_manager)
            
            # Run the scan
            result = engine.run()
            
            # Store the result
            self.scan_results[scan_id] = result
            
            # Process the result to find new targets
            self.process_scan_result(result, target)
            
            logger.info(f"Scan completed for {target}")
            
        except Exception as e:
            logger.error(f"Error scanning {target}: {str(e)}")
            self.scan_results[scan_id] = {'error': str(e)}
    
    def process_scan_result(self, result, source_target):
        """Process scan result to find new targets."""
        # Extract domain from source target
        source_domain = urlparse(source_target).netloc
        
        # Look for links in the result
        if 'links' in result:
            for link in result['links']:
                # Always add discovered links as potential targets
                self.add_target(link)
        
        # Look for subdomains in the result
        if 'subdomains' in result:
            for subdomain in result['subdomains']:
                self.add_target(f"http://{subdomain}")
        
        # Look for IP addresses in the result
        if 'ip_addresses' in result:
            for ip in result['ip_addresses']:
                self.add_target(f"http://{ip}")
    
    def stop(self):
        """Stop the autonomous scanner."""
        logger.info("Stopping autonomous scanner")
        self.stop_event.set()