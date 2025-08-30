# Pin0cchi0 Web UI Guide

## Overview

The Pin0cchi0 Web UI provides a user-friendly interface for managing security scans, viewing vulnerabilities, and configuring the security testing framework. This guide explains how to use the various features of the web interface.

## Getting Started

### Starting the Web UI

To start the Pin0cchi0 Web UI, run the following command from the project root directory:

```bash
python -m web_ui.app
```

Once started, open your web browser and navigate to `http://localhost:5000` to access the interface.

## Dashboard

The dashboard is the main page of the Pin0cchi0 Web UI and provides an overview of your security testing activities.

### Key Components

1. **Active Scans**: Shows currently running scans with progress indicators
2. **Recent Vulnerabilities**: Displays the most recently discovered vulnerabilities
3. **Recent Scans**: Lists recently completed scans with summary information
4. **Start New Scan**: Form to configure and launch a new security scan

### Starting a New Scan

To start a new scan from the dashboard:

1. Enter the target URL in the "Target URL" field
2. Select the scan type:
   - **Full**: Comprehensive scan using all available modules
   - **Quick**: Fast scan focusing on common vulnerabilities
   - **Passive**: Non-intrusive scan that doesn't send active payloads
   - **Custom**: Select specific modules to use
3. If "Custom" is selected, choose the desired modules from the list
4. Click "Start Scan" to begin

## Scan Detail Page

The scan detail page provides in-depth information about a specific scan.

### Key Components

1. **Scan Information**: Basic details about the scan (ID, target, type, start time, status)
2. **Progress**: Visual indicator of scan completion percentage
3. **Vulnerabilities Found**: Table of vulnerabilities discovered during the scan
4. **Scan Log**: Real-time log of scan activities and findings

### Actions

- **Stop Scan**: Halts a currently running scan
- **Export Report**: Generates and downloads a scan report in various formats (PDF, HTML, JSON)
- **Rescan**: Initiates a new scan with the same configuration

## Vulnerabilities Page

The vulnerabilities page provides a comprehensive view of all discovered vulnerabilities across all scans.

### Key Components

1. **Vulnerability Table**: List of all vulnerabilities with details
   - Severity (Critical, High, Medium, Low, Info)
   - Type (XSS, SQL Injection, etc.)
   - Target URL
   - Discovery Date
   - Status (New, Verified, False Positive, Fixed)
2. **Filters**: Options to filter vulnerabilities by various criteria
3. **Export**: Export vulnerability data in various formats

### Vulnerability Detail Modal

Clicking on a vulnerability opens a detailed view with:

1. **Description**: Detailed explanation of the vulnerability
2. **Evidence**: Request/response data demonstrating the vulnerability
3. **Impact**: Potential consequences of the vulnerability
4. **Remediation**: Suggested fixes or mitigations
5. **Actions**: Options to mark as verified, false positive, or fixed

## Configuration

The configuration page allows you to customize Pin0cchi0's behavior.

### General Settings

- **Concurrent Scans**: Maximum number of simultaneous scans
- **Default Scan Type**: The default scan type selected in the new scan form
- **Request Throttling**: Delay between requests to avoid overwhelming targets

### Module Configuration

Customize the behavior of individual testing modules:

- **Enable/Disable**: Toggle specific modules on or off
- **Module Options**: Configure module-specific parameters
- **Custom Payloads**: Add or modify test payloads for various modules

### Proxy Settings

- **Proxy Configuration**: Set up HTTP/HTTPS proxies for outgoing requests
- **Burp Integration**: Configure integration with Burp Suite

## User Management

The user management page allows administrators to manage user accounts.

### User Operations

- **Add User**: Create new user accounts
- **Edit User**: Modify existing user details and permissions
- **Delete User**: Remove user accounts
- **Reset Password**: Reset a user's password

### Role Management

- **Admin**: Full access to all features
- **Analyst**: Can run scans and view results
- **Viewer**: Can only view scan results

## API Access

The Pin0cchi0 Web UI provides a REST API for programmatic access to its functionality.

### API Endpoints

- **GET /api/scans**: List all scans
- **POST /api/scans**: Start a new scan
- **GET /api/scans/{id}**: Get details of a specific scan
- **DELETE /api/scans/{id}**: Stop and delete a scan
- **GET /api/vulnerabilities**: List all vulnerabilities
- **GET /api/vulnerabilities/{id}**: Get details of a specific vulnerability

### API Authentication

API requests require authentication using an API key, which can be generated in the user profile section.

## Troubleshooting

### Common Issues

1. **Web UI Not Starting**: Check if the required dependencies are installed and ports are available
2. **Scan Not Starting**: Verify target URL format and network connectivity
3. **Real-time Updates Not Working**: Ensure WebSocket connections are not blocked by firewalls

### Logs

Web UI logs are stored in the `logs/web_ui.log` file and can be useful for diagnosing issues.

## Keyboard Shortcuts

- **Ctrl+N**: Start a new scan
- **Ctrl+S**: Stop the current scan
- **Ctrl+F**: Open search/filter
- **Ctrl+E**: Export current view
- **Esc**: Close modal dialogs