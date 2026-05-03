#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 DNS Enumeration Module

This module performs DNS enumeration to discover DNS records, zone transfers,
and other DNS-related information.
"""

import os
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory

logger = logging.getLogger('PIN0CCHI0.Recon.DNSEnum')

class DNSEnumModule(ReconModule):
    """Module for DNS enumeration."""
    
    def __init__(self):
        super().__init__(
            name="DNS Enumeration",
            description="Performs DNS enumeration to discover DNS records and zone transfers"
        )
        self.dns_records = {}
        self.nameservers = []
        self.zone_transfer_results = {}
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run DNS enumeration on the target.
        
        Args:
            target (str): Target domain
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for DNS enumeration")
            return {'success': False, 'error': 'No target specified'}
        
        logger.info(f"Starting DNS enumeration on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'dns_enum', timestamp)
        ensure_directory(output_dir)
        
        # Get nameservers
        self.nameservers = self._get_nameservers(target)
        
        # Get DNS records
        self._get_dns_records(target)
        
        # Attempt zone transfers
        if self.nameservers:
            self._attempt_zone_transfers(target)
        
        # Save results
        results = {
            'target': target,
            'nameservers': self.nameservers,
            'dns_records': self.dns_records,
            'zone_transfer_results': self.zone_transfer_results
        }
        
        results_file = os.path.join(output_dir, 'dns_enum_results.json')
        save_json(results, results_file)
        
        logger.info(f"DNS enumeration completed for {target}")
        
        # Add result
        result = {
            'title': f"DNS Enumeration for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.nameservers)} nameservers and {sum(len(records) for records in self.dns_records.values())} DNS records",
            'nameservers': self.nameservers,
            'dns_records': self.dns_records,
            'zone_transfer_results': self.zone_transfer_results,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'nameservers': self.nameservers,
            'dns_records_count': {record_type: len(records) for record_type, records in self.dns_records.items()},
            'zone_transfer_success': any(result.get('success', False) for result in self.zone_transfer_results.values()),
            'output_file': results_file
        }
    
    def _get_nameservers(self, domain):
        """Get nameservers for the domain."""
        logger.info(f"Getting nameservers for {domain}")
        
        cmd = ['dig', 'NS', domain, '+short']
        result = run_command(" ".join(cmd))
        
        nameservers = []
        if result['success']:
            output = result['stdout']
            nameservers = [ns.strip('.') for ns in output.strip().split('\n') if ns.strip()]
            logger.info(f"Found {len(nameservers)} nameservers for {domain}")
        else:
            logger.warning(f"Failed to get nameservers for {domain}: {result.get('error', 'Unknown error')}")
        
        return nameservers
    
    def _get_dns_records(self, domain):
        """Get various DNS records for the domain."""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SOA', 'PTR', 'SRV']
        
        for record_type in record_types:
            logger.info(f"Getting {record_type} records for {domain}")
            
            cmd = ['dig', record_type, domain, '+short']
            result = run_command(" ".join(cmd))
            
            if result['success']:
                output = result['stdout']
                records = [record.strip() for record in output.strip().split('\n') if record.strip()]
                
                if records:
                    self.dns_records[record_type] = records
                    logger.info(f"Found {len(records)} {record_type} records for {domain}")
            else:
                logger.warning(f"Failed to get {record_type} records for {domain}: {result.get('error', 'Unknown error')}")
        
        # Run dnsrecon for additional records
        self._run_dnsrecon(domain)
    
    def _run_dnsrecon(self, domain):
        """Run dnsrecon tool for comprehensive DNS enumeration."""
        logger.info(f"Running dnsrecon on {domain}")
        
        cmd = ['dnsrecon', '-d', domain, '-a']
        result = run_command(" ".join(cmd))
        
        if not result['success']:
            logger.warning(f"dnsrecon failed: {result.get('error', 'Unknown error')}")
    
    def _attempt_zone_transfers(self, domain):
        """Attempt zone transfers from each nameserver."""
        for ns in self.nameservers:
            logger.info(f"Attempting zone transfer from {ns} for {domain}")
            
            cmd = ['dig', 'AXFR', domain, f'@{ns}']
            result = run_command(" ".join(cmd))
            
            if result['success']:
                output = result['stdout']
                
                # Check if zone transfer was successful
                if 'Transfer failed' in output or 'communications error' in output:
                    self.zone_transfer_results[ns] = {
                        'success': False,
                        'message': 'Zone transfer failed or denied'
                    }
                    logger.info(f"Zone transfer from {ns} for {domain} failed or was denied")
                else:
                    # Parse zone transfer results
                    records = []
                    for line in output.strip().split('\n'):
                        if line and not line.startswith(';') and not line.startswith('$'):
                            records.append(line.strip())
                    
                    self.zone_transfer_results[ns] = {
                        'success': True,
                        'records': records
                    }
                    logger.info(f"Zone transfer from {ns} for {domain} successful. Found {len(records)} records.")
            else:
                self.zone_transfer_results[ns] = {
                    'success': False,
                    'message': result.get('error', 'Unknown error')
                }
                logger.warning(f"Zone transfer attempt from {ns} for {domain} failed: {result.get('error', 'Unknown error')}")
        
        # Also try with host command
        for ns in self.nameservers:
            cmd = ['host', '-l', domain, ns]
            result = run_command(" ".join(cmd))
            
            if result['success'] and 'Transfer of' in result['stdout'] and 'failed' not in result['stdout'].lower():
                logger.info(f"Zone transfer with host command from {ns} for {domain} successful")
                
                # If we didn't already have a successful transfer from this nameserver
                if not self.zone_transfer_results.get(ns, {}).get('success', False):
                    records = [line.strip() for line in result['stdout'].strip().split('\n') if line.strip() and not line.startswith(';')]
                    
                    self.zone_transfer_results[ns] = {
                        'success': True,
                        'records': records
                    }