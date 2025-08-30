# Pin0cchi0 CLI Guide

## Overview

The Pin0cchi0 Command Line Interface (CLI) provides a powerful way to run security scans directly from your terminal. This guide explains how to use the CLI tool effectively on Linux systems.

## Installation

Ensure you have installed all the required dependencies:

```bash
pip install -r requirements.txt
```

Make the CLI script executable:

```bash
chmod +x pin0cchi0-cli.py
```

## Basic Usage

The basic syntax for using the Pin0cchi0 CLI is:

```bash
python pin0cchi0-cli.py [options] -t TARGET
```

### Examples

```bash
# Run a basic scan against a target
python pin0cchi0-cli.py -t https://example.com

# Run a scan with specific modules
python pin0cchi0-cli.py -t https://example.com -m xss,sqli,csrf

# Run a full scan with all modules
python pin0cchi0-cli.py -t https://example.com --full

# Run a passive scan (non-intrusive)
python pin0cchi0-cli.py -t https://example.com --passive

# Run an autonomous scan starting with a seed target
python pin0cchi0-cli.py --autonomous --seed-target https://example.com
```

## Command Line Options

### Target Selection

```
-t, --target URL           Target URL to scan
--targets-file FILE        File containing list of targets (one per line)
--seed-target URL          Initial target for autonomous scanning
```

### Scan Types

```
--full                     Run a comprehensive scan with all modules
--quick                    Run a fast scan with essential modules
--passive                  Run a non-intrusive scan
--custom                   Run a custom scan (requires -m/--modules)
--autonomous               Run in autonomous discovery and scanning mode
```

### Module Selection

```
-m, --modules MODULES      Comma-separated list of modules to use
--list-modules             Display available modules
--exclude-modules MODULES  Comma-separated list of modules to exclude
```

### Authentication

```
--auth-type TYPE           Authentication type (basic, form, header, oauth)
--username USER            Username for authentication
--password PASS            Password for authentication
--auth-file FILE           File containing authentication details (JSON)
```

### Proxy Settings

```
--proxy URL                Proxy URL (e.g., http://127.0.0.1:8080)
--proxy-auth USER:PASS     Proxy authentication credentials
```

### Output Control

```
-o, --output FILE          Output file for scan results
--format FORMAT            Output format (json, html, txt, csv)
-v, --verbose              Enable verbose output
--quiet                    Suppress all output except results
--no-color                 Disable colored output
```

### Scan Behavior

```
--threads NUM              Number of concurrent threads (default: 5)
--timeout SEC              Request timeout in seconds (default: 10)
--delay SEC                Delay between requests in seconds (default: 0)
--user-agent STRING        Custom User-Agent string
--cookies STRING           Custom cookies (format: name1=value1;name2=value2)
--headers FILE             File containing custom HTTP headers (JSON)
--max-depth NUM           Maximum crawl depth (default: 3)
--scope-constraint TYPE    Scope constraint (strict, relaxed, domain-only)
```

### Advanced Options

```
--config FILE              Custom configuration file
--api-keys FILE            File containing API keys (JSON)
--debug                    Enable debug mode
--disable-ssl-verify       Disable SSL certificate verification
--follow-redirects         Follow HTTP redirects (default: true)
--max-redirects NUM        Maximum number of redirects to follow (default: 5)
```

## Module Management

### Listing Available Modules

To see all available testing modules:

```bash
python pin0cchi0-cli.py --list-modules
```

This will display a list of modules with descriptions, categorized by type.

### Using Specific Modules

To use specific modules for testing:

```bash
python pin0cchi0-cli.py -t https://example.com -m xss,sqli,csrf,ssrf
```

### Excluding Modules

To run all modules except specific ones:

```bash
python pin0cchi0-cli.py -t https://example.com --full --exclude-modules xxe,ssti
```

## Autonomous Scanning

Autonomous scanning allows Pin0cchi0 to discover and test targets automatically.

```bash
python pin0cchi0-cli.py --autonomous --seed-target https://example.com --depth 2
```

Additional autonomous scanning options:

```
--depth NUM                Maximum discovery depth (default: 1)
--max-targets NUM          Maximum number of targets to scan (default: 10)
--discovery-methods LIST   Comma-separated list of discovery methods (dns,whois,shodan)
--shodan-key KEY           Shodan API key for enhanced discovery
```

## Output Formats

Pin0cchi0 supports multiple output formats:

```bash
# Output as JSON
python pin0cchi0-cli.py -t https://example.com -o results.json --format json

# Output as HTML report
python pin0cchi0-cli.py -t https://example.com -o report.html --format html

# Output as plain text
python pin0cchi0-cli.py -t https://example.com -o results.txt --format txt

# Output as CSV
python pin0cchi0-cli.py -t https://example.com -o vulnerabilities.csv --format csv
```

## Configuration Files

You can use configuration files to store complex scan settings:

```bash
python pin0cchi0-cli.py --config my_scan_config.json
```

Example configuration file (my_scan_config.json):

```json
{
  "target": "https://example.com",
  "modules": ["xss", "sqli", "csrf", "ssrf"],
  "threads": 10,
  "output": "scan_results.json",
  "format": "json",
  "proxy": "http://127.0.0.1:8080",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
  "max_depth": 2,
  "timeout": 15,
  "delay": 0.5
}
```

## Environment Variables

Pin0cchi0 CLI supports configuration via environment variables:

```bash
# Set proxy
export PIN0CCHI0_PROXY="http://127.0.0.1:8080"

# Set API keys
export PIN0CCHI0_SHODAN_KEY="your_shodan_api_key"

# Set default output format
export PIN0CCHI0_OUTPUT_FORMAT="json"
```

## Exit Codes

The CLI returns different exit codes based on the scan result:

- 0: Scan completed successfully with no vulnerabilities found
- 1: Scan completed successfully with vulnerabilities found
- 2: Scan failed due to an error
- 3: Invalid command-line arguments
- 4: Configuration error

## Integrating with Other Tools

### Piping Results

You can pipe results to other tools:

```bash
python pin0cchi0-cli.py -t https://example.com --format json | jq '.vulnerabilities'
```

### Continuous Integration

For CI/CD pipelines, you can use the exit codes to determine if vulnerabilities were found:

```bash
python pin0cchi0-cli.py -t https://example.com --format json -o results.json
if [ $? -eq 1 ]; then
  echo "Vulnerabilities found!"
  exit 1
fi
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the script is executable (`chmod +x pin0cchi0-cli.py`)
2. **Module Not Found**: Check that all dependencies are installed
3. **Connection Errors**: Verify network connectivity and proxy settings
4. **API Key Issues**: Ensure API keys are correctly configured for services like Shodan

### Debug Mode

For detailed debugging information:

```bash
python pin0cchi0-cli.py -t https://example.com --debug
```

### Logs

CLI logs are stored in the `logs/cli.log` file and can be useful for diagnosing issues.