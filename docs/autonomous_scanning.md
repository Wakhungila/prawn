# Pin0cchi0 Autonomous Scanning Guide

## Overview

The autonomous scanning feature in Pin0cchi0 enables the framework to automatically discover and test targets without continuous human intervention. This guide explains how the autonomous scanning works and how to configure it effectively.

## How Autonomous Scanning Works

The autonomous scanning process follows these key steps:

1. **Initial Target Seeding**: Start with one or more seed targets provided by the user
2. **Target Discovery**: Discover related targets through various methods:
   - DNS enumeration (subdomains, related domains)
   - WHOIS data analysis
   - Shodan API integration
   - Content analysis (links, references)
3. **Target Prioritization**: Rank discovered targets based on:
   - Relevance to original seed targets
   - Potential security impact
   - Technology stack detected
4. **Intelligent Testing**: Apply appropriate testing modules based on detected technologies
5. **Result Processing**: Analyze scan results to discover additional targets
6. **Recursive Scanning**: Continue the discovery-scan cycle up to the configured depth

## Using Autonomous Scanning

### Via Web UI

1. Navigate to the dashboard
2. Click "Start New Scan"
3. Enter your seed target URL
4. Select "Autonomous" scan type
5. Configure discovery options (optional)
6. Click "Start Scan"

### Via Command Line

```bash
python pin0cchi0-cli.py --autonomous --seed-target https://example.com
```

Additional CLI options for autonomous scanning:

```
--depth NUM                Maximum discovery depth (default: 1)
--max-targets NUM          Maximum number of targets to scan (default: 10)
--discovery-methods LIST   Comma-separated list of discovery methods (dns,whois,shodan)
--shodan-key KEY           Shodan API key for enhanced discovery
```

## Configuration

The autonomous scanning behavior can be customized through the `config/autonomous_config.json` file:

```json
{
  "target_discovery": {
    "methods": ["dns", "whois", "shodan", "content"],
    "max_depth": 2,
    "max_targets_per_level": 10,
    "max_total_targets": 50,
    "target_filters": {
      "include_subdomains": true,
      "include_related_domains": true,
      "include_ip_space": false
    }
  },
  "scan_modules": {
    "auto_select": true,
    "default_modules": ["xss", "sqli", "ssrf", "open_redirect"],
    "technology_mapping": {
      "wordpress": ["wp_plugin_scanner", "wp_theme_scanner"],
      "php": ["php_vulnerabilities", "file_inclusion"],
      "java": ["deserialization", "xxe"],
      "node": ["nosql_injection", "prototype_pollution"]
    }
  },
  "shodan_api": {
    "key": "YOUR_SHODAN_API_KEY",
    "max_results": 100
  },
  "reporting": {
    "auto_generate": true,
    "formats": ["json", "html"],
    "include_evidence": true
  },
  "throttling": {
    "requests_per_second": 5,
    "delay_between_scans": 2,
    "max_concurrent_scans": 3
  },
  "authentication": {
    "attempt_discovery": true,
    "default_credentials": false
  },
  "proxy": {
    "enabled": false,
    "url": "http://127.0.0.1:8080"
  },
  "user_agents": [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
  ],
  "exclusions": {
    "patterns": [
      "logout",
      "signout",
      "delete",
      "remove"
    ],
    "domains": [
      "example-staging.com",
      "test.example.com"
    ]
  }
}
```

## Discovery Methods

### DNS Enumeration

The DNS discovery method finds subdomains and related domains through:

- DNS zone transfers (if allowed)
- Subdomain brute forcing
- DNS record analysis
- Certificate transparency logs

### WHOIS Analysis

The WHOIS discovery method identifies related targets by analyzing:

- Domain registrant information
- Administrative contacts
- Technical contacts
- Name servers
- Related domain registrations

### Shodan Integration

The Shodan discovery method leverages the Shodan API to find:

- IP ranges associated with the target
- Similar web applications
- Internet-facing services
- Potential vulnerabilities

### Content Analysis

The content discovery method analyzes web content to find:

- Links to other applications
- References to internal systems
- API endpoints
- Third-party integrations

## Target Prioritization

Targets are prioritized based on several factors:

1. **Relevance Score**: How closely related the target is to the seed target
2. **Technology Score**: Based on detected technologies and their known vulnerabilities
3. **Exposure Score**: How exposed the target is (public-facing, authentication requirements)
4. **Content Score**: Based on sensitive content or functionality detected

## Intelligent Module Selection

The autonomous scanner automatically selects appropriate testing modules based on:

1. **Detected Technologies**: Applies technology-specific modules
2. **Server Headers**: Targets server-specific vulnerabilities
3. **Content Analysis**: Selects modules based on detected content types
4. **Previous Results**: Adapts based on vulnerabilities found in related targets

## Throttling and Rate Limiting

To avoid overwhelming targets or triggering security controls, the autonomous scanner implements:

1. **Request Rate Limiting**: Controls requests per second
2. **Scan Delays**: Adds delays between scans of related targets
3. **Concurrency Control**: Limits simultaneous scans
4. **Adaptive Throttling**: Adjusts rates based on target responses

## Best Practices

### Ethical Considerations

1. **Authorization**: Only scan targets you have permission to test
2. **Scope Management**: Use exclusion patterns to avoid testing sensitive areas
3. **Rate Limiting**: Configure appropriate throttling to avoid denial of service
4. **Data Handling**: Handle discovered information responsibly

### Performance Optimization

1. **Start Small**: Begin with a low depth and increase gradually
2. **Target Filtering**: Use filters to focus on relevant targets
3. **Module Selection**: Limit modules to those relevant to your testing goals
4. **Resource Allocation**: Adjust concurrency based on available system resources

## Troubleshooting

### Common Issues

1. **Discovery Timeout**: Increase timeouts or reduce concurrent operations
2. **API Rate Limiting**: Check Shodan API usage limits
3. **False Positives**: Adjust module sensitivity or use exclusion patterns
4. **Resource Exhaustion**: Reduce max_targets or max_depth settings

### Logs

Autonomous scanning logs are stored in the `logs/autonomous.log` file and provide detailed information about the discovery and scanning process.

## Advanced Usage

### Custom Discovery Plugins

You can extend the autonomous scanner with custom discovery plugins by creating Python modules in the `modules/autonomous/discovery/` directory.

### Integration with External Tools

The autonomous scanner can be integrated with external tools through the API or by using the results output in various formats.

### Continuous Monitoring

By scheduling regular autonomous scans, you can implement continuous security monitoring of your attack surface.