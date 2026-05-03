#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Network Mapper Module

This module performs network mapping and topology discovery using tools like
traceroute, nmap, and other network discovery techniques.
"""

import os
import json
import logging
from datetime import datetime

from core.base_module import ReconModule
from core.utils import run_command, save_json, ensure_directory

logger = logging.getLogger('PIN0CCHI0.Recon.NetworkMapper')

class NetworkMapperModule(ReconModule):
    """Module for network mapping and topology discovery."""
    
    def __init__(self):
        super().__init__(
            name="Network Mapper",
            description="Performs network mapping and topology discovery"
        )
        self.network_map = {}
        self.traceroute_results = {}
        self.alive_hosts = []
        self.network_services = {}
    
    def run(self, target=None, output_dir=None, config=None, **kwargs):
        """
        Run network mapping on the target.
        
        Args:
            target (str): Target IP or network range (e.g., 192.168.1.0/24)
            output_dir (str): Directory to save results
            config (dict): Module configuration
            
        Returns:
            dict: Module results
        """
        if not target:
            logger.error("No target specified for network mapping")
            return {'success': False, 'error': 'No target specified'}
        
        logger.info(f"Starting network mapping on {target}")
        
        # Create output directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = output_dir or os.path.join('output', 'recon', 'network_map', timestamp)
        ensure_directory(output_dir)
        
        # Run network mapping tools
        self._discover_alive_hosts(target)
        
        if self.alive_hosts:
            self._run_traceroute(self.alive_hosts)
            self._discover_network_services(self.alive_hosts)
            self._generate_network_map()
        
        # Save results
        results = {
            'target': target,
            'alive_hosts': self.alive_hosts,
            'traceroute_results': self.traceroute_results,
            'network_services': self.network_services,
            'network_map': self.network_map
        }
        
        results_file = os.path.join(output_dir, 'network_map_results.json')
        save_json(results, results_file)
        
        logger.info(f"Network mapping completed for {target}. Found {len(self.alive_hosts)} alive hosts.")
        
        # Add result
        result = {
            'title': f"Network Mapping for {target}",
            'severity': 'Info',
            'description': f"Discovered {len(self.alive_hosts)} alive hosts and mapped network topology",
            'alive_hosts': self.alive_hosts,
            'network_map': self.network_map,
            'output_file': results_file
        }
        
        self.add_result(result)
        
        return {
            'success': True,
            'alive_hosts_count': len(self.alive_hosts),
            'services_count': sum(len(services) for services in self.network_services.values()),
            'output_file': results_file
        }
    
    def _discover_alive_hosts(self, target):
        """Discover alive hosts in the target network."""
        logger.info(f"Discovering alive hosts in {target}")
        
        # Use nmap for host discovery
        cmd = "nmap -sn -T4 " + target + " -oG -"
        result = run_command(cmd)
        
        if result['success']:
            output = result['stdout']
            
            # Parse nmap output to find alive hosts
            for line in output.strip().split('\n'):
                if 'Status: Up' in line:
                    # Extract IP address
                    parts = line.split()
                    for part in parts:
                        if part.startswith('Host:'):
                            ip = part.split('Host:')[1].strip()
                            if ip and ip not in self.alive_hosts:
                                self.alive_hosts.append(ip)
            
            logger.info(f"Found {len(self.alive_hosts)} alive hosts in {target}")
        else:
            logger.warning(f"Host discovery failed for {target}: {result.get('error', 'Unknown error')}")
        
        # If no hosts found with nmap, try ping sweep
        if not self.alive_hosts:
            self._run_ping_sweep(target)
    
    def _run_ping_sweep(self, target):
        """Run ping sweep to discover alive hosts."""
        logger.info(f"Running ping sweep on {target}")
        
        # Use fping for ping sweep
        cmd = "fping -a -g " + target
        result = run_command(cmd)
        
        if result['success']:
            output = result['stdout']
            
            # Parse fping output
            for line in output.strip().split('\n'):
                ip = line.strip()
                if ip and ip not in self.alive_hosts:
                    self.alive_hosts.append(ip)
            
            logger.info(f"Ping sweep found {len(self.alive_hosts)} alive hosts in {target}")
        else:
            logger.warning(f"Ping sweep failed for {target}: {result.get('error', 'Unknown error')}")
    
    def _run_traceroute(self, hosts):
        """Run traceroute to discover network paths."""
        logger.info(f"Running traceroute on {len(hosts)} hosts")
        
        for host in hosts:
            logger.debug(f"Running traceroute to {host}")
            
            # Use traceroute command
            cmd = "traceroute -n " + host
            result = run_command(cmd)
            
            if result['success']:
                output = result['stdout']
                
                # Parse traceroute output
                hops = []
                for line in output.strip().split('\n'):
                    if line.startswith(' '):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        hop_num = int(parts[0])
                        hop_ip = parts[1] if parts[1] != '*' else None
                        
                        if hop_ip:
                            hops.append({
                                'hop': hop_num,
                                'ip': hop_ip
                            })
                
                self.traceroute_results[host] = hops
                logger.debug(f"Traceroute to {host} completed with {len(hops)} hops")
            else:
                logger.warning(f"Traceroute failed for {host}: {result.get('error', 'Unknown error')}")
    
    def _discover_network_services(self, hosts):
        """Discover network services on alive hosts."""
        logger.info(f"Discovering network services on {len(hosts)} hosts")
        
        for host in hosts:
            logger.debug(f"Scanning services on {host}")
            
            # Use nmap for service discovery
            cmd = "nmap -sV -T4 -F " + host + " -oG -"
            result = run_command(cmd)
            
            if result['success']:
                output = result['stdout']
                
                # Parse nmap output to find services
                services = []
                for line in output.strip().split('\n'):
                    if 'Ports:' in line:
                        ports_part = line.split('Ports:')[1].strip()
                        port_entries = ports_part.split(', ')
                        
                        for entry in port_entries:
                            parts = entry.split('/')
                            if len(parts) >= 7:
                                port = parts[0].strip()
                                state = parts[1].strip()
                                protocol = parts[2].strip()
                                service = parts[4].strip()
                                version = parts[6].strip()
                                
                                if state == 'open':
                                    services.append({
                                        'port': port,
                                        'protocol': protocol,
                                        'service': service,
                                        'version': version
                                    })
                
                self.network_services[host] = services
                logger.debug(f"Found {len(services)} open services on {host}")
            else:
                logger.warning(f"Service discovery failed for {host}: {result.get('error', 'Unknown error')}")
    
    def _generate_network_map(self):
        """Generate network map from collected data."""
        logger.info("Generating network map")
        
        # Create nodes for all hosts
        nodes = []
        for host in self.alive_hosts:
            node = {
                'id': host,
                'type': 'host',
                'services': self.network_services.get(host, [])
            }
            nodes.append(node)
        
        # Create edges from traceroute data
        edges = []
        for target, hops in self.traceroute_results.items():
            for i in range(len(hops) - 1):
                source = hops[i]['ip']
                destination = hops[i + 1]['ip']
                
                # Check if edge already exists
                edge_exists = False
                for edge in edges:
                    if edge['source'] == source and edge['target'] == destination:
                        edge_exists = True
                        break
                
                if not edge_exists:
                    edges.append({
                        'source': source,
                        'target': destination
                    })
        
        # Add router nodes from traceroute data
        for target, hops in self.traceroute_results.items():
            for hop in hops:
                hop_ip = hop['ip']
                
                # Check if node already exists
                node_exists = False
                for node in nodes:
                    if node['id'] == hop_ip:
                        node_exists = True
                        break
                
                if not node_exists:
                    nodes.append({
                        'id': hop_ip,
                        'type': 'router',
                        'services': []
                    })
        
        self.network_map = {
            'nodes': nodes,
            'edges': edges
        }
        
        logger.info(f"Network map generated with {len(nodes)} nodes and {len(edges)} edges")