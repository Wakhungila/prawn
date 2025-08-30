#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Command Line Interface

This script provides a command-line interface for the PIN0CCHI0 security testing framework,
allowing it to be used on Linux and other command-line environments.
"""

import os
import sys
import json
import argparse
import logging
import time
from datetime import datetime

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('pin0cchi0.cli')

# Add the parent directory to the path so we can import the PIN0CCHI0 modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.engine import Engine
from core.config_manager import ConfigManager
from core.module_manager import ModuleManager

class PIN0CCHI0_CLI:
    """Command Line Interface for PIN0CCHI0 security testing framework."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.config_manager = ConfigManager()
        self.module_manager = ModuleManager(self.config_manager)
        self.engine = Engine(self.config_manager, self.module_manager)
        
        # Register callbacks
        self.engine.set_callback('progress', self.progress_callback)
        self.engine.set_callback('vulnerability', self.vulnerability_callback)
        
        # Initialize counters
        self.vulnerabilities_found = 0
        self.modules_completed = 0
        self.total_modules = 0
        
    def progress_callback(self, module_name, progress, message):
        """Callback for scan progress updates."""
        if progress == 100 and message == "Module completed":
            self.modules_completed += 1
            logger.info(f"Module {module_name} completed ({self.modules_completed}/{self.total_modules})")
        else:
            logger.info(f"[{module_name}] {progress}%: {message}")
    
    def vulnerability_callback(self, vulnerability):
        """Callback for vulnerability findings."""
        self.vulnerabilities_found += 1
        severity = vulnerability.get('severity', 'Unknown').upper()
        vuln_type = vulnerability.get('type', 'Unknown')
        url = vulnerability.get('url', 'Unknown')
        
        # Color coding based on severity
        color_code = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
            'INFO': '\033[96m',      # Cyan
            'Unknown': '\033[97m'    # White
        }.get(severity, '\033[97m')
        
        reset_color = '\033[0m'
        
        logger.info(f"{color_code}[{severity}] {vuln_type} found at {url}{reset_color}")
    
    def run(self, args):
        """Run the CLI with the provided arguments."""
        # Parse command line arguments
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        # Handle help command
        if parsed_args.command == 'help':
            parser.print_help()
            return 0
        
        # Handle list command
        if parsed_args.command == 'list':
            return self.list_modules()
        
        # Handle scan command
        if parsed_args.command == 'scan':
            return self.run_scan(parsed_args)
        
        # Handle version command
        if parsed_args.command == 'version':
            print("PIN0CCHI0 Security Testing Framework v0.1.0")
            return 0
        
        # If no command or invalid command
        parser.print_help()
        return 1
    
    def create_parser(self):
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description='PIN0CCHI0 Security Testing Framework - Command Line Interface',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # Help command
        subparsers.add_parser('help', help='Show this help message')
        
        # Version command
        subparsers.add_parser('version', help='Show version information')
        
        # List command
        list_parser = subparsers.add_parser('list', help='List available modules')
        list_parser.add_argument('--category', help='Filter modules by category')
        
        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Run a security scan')
        scan_parser.add_argument('target', help='Target URL or IP address')
        scan_parser.add_argument('--output', '-o', help='Output directory for scan results')
        scan_parser.add_argument('--modules', '-m', help='Comma-separated list of modules to run')
        scan_parser.add_argument('--exclude', '-e', help='Comma-separated list of modules to exclude')
        scan_parser.add_argument('--config', '-c', help='Path to configuration file')
        scan_parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
        scan_parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output except for results')
        scan_parser.add_argument('--json', '-j', action='store_true', help='Output results in JSON format')
        scan_parser.add_argument('--autonomous', '-a', action='store_true', help='Run in fully autonomous mode')
        
        return parser
    
    def list_modules(self):
        """List available modules."""
        modules = self.module_manager.get_modules()
        
        print("\nAvailable Modules:")
        print("-" * 80)
        print(f"{'Name':<30} {'Category':<15} {'Description':<35}")
        print("-" * 80)
        
        for module in modules:
            name = module.name if hasattr(module, 'name') else 'Unknown'
            category = module.category if hasattr(module, 'category') else 'Unknown'
            description = module.description if hasattr(module, 'description') else 'No description'
            print(f"{name:<30} {category:<15} {description:<35}")
        
        print("\nUse 'pin0cchi0-cli.py scan <target> --modules <module1,module2>' to run specific modules")
        return 0
    
    def run_scan(self, args):
        """Run a security scan with the provided arguments."""
        # Set up configuration
        scan_config = {
            'target': args.target,
            'output_dir': args.output or f"results/{int(time.time())}-{args.target.replace('://', '-').replace('/', '-')}"
        }
        
        # Load custom configuration if provided
        if args.config:
            try:
                with open(args.config, 'r') as f:
                    custom_config = json.load(f)
                    scan_config.update(custom_config)
            except Exception as e:
                logger.error(f"Error loading configuration file: {str(e)}")
                return 1
        
        # Set up modules to run
        if args.modules:
            scan_config['modules'] = args.modules.split(',')
        
        # Set up modules to exclude
        if args.exclude:
            scan_config['exclude_modules'] = args.exclude.split(',')
        
        # Set up autonomous mode
        if args.autonomous:
            scan_config['autonomous'] = True
            logger.info("Running in autonomous mode")
        
        # Set up verbosity
        if args.verbose:
            logging.getLogger('pin0cchi0').setLevel(logging.DEBUG)
        elif args.quiet:
            logging.getLogger('pin0cchi0').setLevel(logging.WARNING)
        
        # Create output directory
        os.makedirs(scan_config['output_dir'], exist_ok=True)
        
        # Update engine configuration
        self.engine.config.update(scan_config)
        
        # Count total modules to run
        self.total_modules = len(self.module_manager.get_modules())
        if 'modules' in scan_config:
            self.total_modules = len(scan_config['modules'])
        if 'exclude_modules' in scan_config:
            self.total_modules -= len(scan_config['exclude_modules'])
        
        # Print scan information
        print("\n" + "=" * 80)
        print(f"PIN0CCHI0 Security Scan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print(f"Target: {args.target}")
        print(f"Output Directory: {scan_config['output_dir']}")
        if 'modules' in scan_config:
            print(f"Modules: {', '.join(scan_config['modules'])}")
        if 'exclude_modules' in scan_config:
            print(f"Excluded Modules: {', '.join(scan_config['exclude_modules'])}")
        print("=" * 80 + "\n")
        
        # Run the scan
        try:
            start_time = time.time()
            logger.info(f"Starting scan of {args.target}")
            
            result = self.engine.run()
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Print scan summary
            print("\n" + "=" * 80)
            print(f"Scan Completed - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)
            print(f"Target: {args.target}")
            print(f"Duration: {int(duration // 60)} minutes, {int(duration % 60)} seconds")
            print(f"Vulnerabilities Found: {self.vulnerabilities_found}")
            print(f"Modules Completed: {self.modules_completed}/{self.total_modules}")
            print(f"Results saved to: {scan_config['output_dir']}")
            print("=" * 80 + "\n")
            
            # Output results in JSON format if requested
            if args.json:
                result_file = os.path.join(scan_config['output_dir'], 'results.json')
                with open(result_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"JSON results saved to: {result_file}")
            
            return 0
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            return 130  # Standard exit code for SIGINT
            
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            return 1

def main():
    """Main function."""
    cli = PIN0CCHI0_CLI()
    return cli.run(sys.argv[1:])

if __name__ == '__main__':
    sys.exit(main())