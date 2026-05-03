#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN Configuration Manager

This module handles loading, validating, and providing access to configuration settings
for the PRAWN framework.
"""

import os
import yaml
import logging

logger = logging.getLogger('PRAWN.ConfigManager')

class ConfigManager:
    """Configuration manager for PRAWN."""
    
    def __init__(self, config_file=None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file (str): Path to configuration file
        """
        self.config_file = config_file or os.path.join('config', 'default.yaml')
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = yaml.safe_load(f)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                logger.warning(f"Configuration file {self.config_file} not found. Using default settings.")
                self.config = self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self.config = self._get_default_config()
    
    def _get_default_config(self):
        """Get default configuration settings."""
        return {
            'general': {
                'threads': 10,
                'timeout': 30,
                'user_agent': 'PRAWN/0.1.0',
                'verbose': False
            },
            'recon': {
                'enabled': True,
                'subdomain_enumeration': True,
                'port_scanning': True,
                'service_detection': True,
                'web_crawling': True,
                'screenshot': True
            },
            'vuln_testing': {
                'enabled': True,
                'xss': True,
                'sqli': True,
                'ssrf': True,
                'xxe': True,
                'file_inclusion': True,
                'command_injection': True,
                'path_traversal': True,
                'open_redirect': True,
                'csrf': True,
                'cors': True
            },
            'exploitation': {
                'enabled': True,
                'auto_exploit': False,  # Default to false for safety
                'exploit_xss': True,
                'exploit_sqli': True,
                'exploit_rce': True
            },
            'reporting': {
                'output_format': 'markdown',
                'include_screenshots': True,
                'include_poc': True,
                'include_remediation': True
            },
            'tools': {
                'nmap_path': 'nmap',
                'sqlmap_path': 'sqlmap',
                'ffuf_path': 'ffuf',
                'nuclei_path': 'nuclei',
                'burp_proxy': 'http://127.0.0.1:8080'
            }
        }
    
    def get(self, section, key=None, default=None):
        """
        Get configuration value.
        
        Args:
            section (str): Configuration section
            key (str, optional): Configuration key
            default (any, optional): Default value if key not found
            
        Returns:
            Configuration value or default
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """
        Set configuration value.
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value (any): Configuration value
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def save(self, config_file=None):
        """
        Save configuration to file.
        
        Args:
            config_file (str, optional): Path to save configuration file
        """
        save_path = config_file or self.config_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            
            logger.info(f"Configuration saved to {save_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False