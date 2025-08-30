// PIN0CCHI0 Web UI Main JavaScript

// Initialize Socket.IO connection
let socket;

// Initialize scan data storage
let activeScanData = {};
let recentVulnerabilities = [];
let recentScans = [];

// DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize Socket.IO if available
    if (typeof io !== 'undefined') {
        initializeSocketIO();
    }

    // Initialize event listeners
    initializeEventListeners();

    // Load initial data
    loadDashboardData();
});

// Initialize Socket.IO connection
function initializeSocketIO() {
    socket = io();

    // Listen for scan updates
    socket.on('scan_update', function(data) {
        console.log('Received scan update:', data);
        updateScanData(data);
    });

    // Listen for vulnerability updates
    socket.on('vulnerability_found', function(data) {
        console.log('Received vulnerability:', data);
        addVulnerability(data);
    });

    // Listen for log updates
    socket.on('log_update', function(data) {
        console.log('Received log update:', data);
        updateScanLog(data);
    });

    // Handle connection
    socket.on('connect', function() {
        console.log('Connected to server');
        showToast('Connected to server', 'success');
    });

    // Handle disconnection
    socket.on('disconnect', function() {
        console.log('Disconnected from server');
        showToast('Disconnected from server', 'warning');
    });
}

// Initialize event listeners
function initializeEventListeners() {
    // New scan form submission
    const newScanForm = document.getElementById('new-scan-form');
    if (newScanForm) {
        newScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startNewScan();
        });
    }

    // Module selection cards
    const moduleCards = document.querySelectorAll('.module-card');
    moduleCards.forEach(card => {
        card.addEventListener('click', function() {
            this.classList.toggle('selected');
            const checkbox = this.querySelector('input[type="checkbox"]');
            if (checkbox) {
                checkbox.checked = !checkbox.checked;
            }
        });
    });

    // Scan type selection
    const scanTypeRadios = document.querySelectorAll('input[name="scan_type"]');
    scanTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            updateModuleSelection(this.value);
        });
    });

    // Stop scan buttons
    document.addEventListener('click', function(e) {
        if (e.target && e.target.classList.contains('stop-scan-btn')) {
            const scanId = e.target.getAttribute('data-scan-id');
            stopScan(scanId);
        }
    });

    // View scan details buttons
    document.addEventListener('click', function(e) {
        if (e.target && e.target.classList.contains('view-scan-btn')) {
            const scanId = e.target.getAttribute('data-scan-id');
            window.location.href = `/scan/${scanId}`;
        }
    });
}

// Load dashboard data
function loadDashboardData() {
    // Fetch active scans
    fetch('/api/scans/active')
        .then(response => response.json())
        .then(data => {
            activeScanData = data;
            updateActiveScansUI();
        })
        .catch(error => {
            console.error('Error fetching active scans:', error);
        });

    // Fetch recent vulnerabilities
    fetch('/api/vulnerabilities/recent')
        .then(response => response.json())
        .then(data => {
            recentVulnerabilities = data;
            updateRecentVulnerabilitiesUI();
        })
        .catch(error => {
            console.error('Error fetching recent vulnerabilities:', error);
        });

    // Fetch recent scans
    fetch('/api/scans/recent')
        .then(response => response.json())
        .then(data => {
            recentScans = data;
            updateRecentScansUI();
        })
        .catch(error => {
            console.error('Error fetching recent scans:', error);
        });

    // Update statistics
    updateStatistics();
}

// Start a new scan
function startNewScan() {
    const targetUrl = document.getElementById('target_url').value;
    const scanType = document.querySelector('input[name="scan_type"]:checked').value;
    
    // Get selected modules
    const selectedModules = [];
    document.querySelectorAll('.module-card.selected input[type="checkbox"]').forEach(checkbox => {
        selectedModules.push(checkbox.value);
    });

    // Create scan configuration
    const scanConfig = {
        target_url: targetUrl,
        scan_type: scanType,
        modules: selectedModules
    };

    // Send request to start scan
    fetch('/api/scan/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanConfig)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(`Scan started for ${targetUrl}`, 'success');
            // Add to active scans
            activeScanData[data.scan_id] = {
                id: data.scan_id,
                target: targetUrl,
                type: scanType,
                status: 'running',
                progress: 0,
                start_time: new Date().toISOString(),
                vulnerabilities: []
            };
            updateActiveScansUI();
            
            // Reset form
            document.getElementById('new-scan-form').reset();
        } else {
            showToast(`Failed to start scan: ${data.error}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showToast('Error starting scan', 'danger');
    });
}

// Stop a running scan
function stopScan(scanId) {
    fetch(`/api/scan/${scanId}/stop`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(`Scan ${scanId} stopped`, 'success');
            if (activeScanData[scanId]) {
                activeScanData[scanId].status = 'stopped';
                updateActiveScansUI();
            }
        } else {
            showToast(`Failed to stop scan: ${data.error}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error stopping scan:', error);
        showToast('Error stopping scan', 'danger');
    });
}

// Update scan data with new information
function updateScanData(data) {
    const scanId = data.id;
    
    // Update or add scan data
    if (!activeScanData[scanId]) {
        activeScanData[scanId] = data;
    } else {
        Object.assign(activeScanData[scanId], data);
    }
    
    // Update UI
    updateActiveScansUI();
    
    // If scan is complete, move to recent scans
    if (data.status === 'completed' || data.status === 'failed') {
        setTimeout(() => {
            delete activeScanData[scanId];
            recentScans.unshift(data);
            // Keep only the 10 most recent scans
            if (recentScans.length > 10) {
                recentScans.pop();
            }
            updateActiveScansUI();
            updateRecentScansUI();
        }, 5000); // Keep in active scans for 5 seconds before moving
    }
    
    // Update statistics
    updateStatistics();
}

// Add a new vulnerability
function addVulnerability(data) {
    // Add to scan's vulnerabilities if it exists
    const scanId = data.scan_id;
    if (activeScanData[scanId]) {
        if (!activeScanData[scanId].vulnerabilities) {
            activeScanData[scanId].vulnerabilities = [];
        }
        activeScanData[scanId].vulnerabilities.push(data);
    }
    
    // Add to recent vulnerabilities
    recentVulnerabilities.unshift(data);
    // Keep only the 10 most recent vulnerabilities
    if (recentVulnerabilities.length > 10) {
        recentVulnerabilities.pop();
    }
    
    // Update UI
    updateRecentVulnerabilitiesUI();
    
    // Show notification
    showToast(`New ${data.severity} vulnerability found: ${data.type}`, 'warning');
    
    // Update statistics
    updateStatistics();
}

// Update scan log
function updateScanLog(data) {
    const scanLogElement = document.getElementById(`scan-log-${data.scan_id}`);
    if (scanLogElement) {
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-level-${data.level.toLowerCase()}`;
        
        const timeSpan = document.createElement('span');
        timeSpan.className = 'log-time';
        timeSpan.textContent = new Date().toLocaleTimeString();
        
        logEntry.appendChild(timeSpan);
        logEntry.appendChild(document.createTextNode(` ${data.message}`));
        
        scanLogElement.appendChild(logEntry);
        scanLogElement.scrollTop = scanLogElement.scrollHeight;
    }
}

// Update module selection based on scan type
function updateModuleSelection(scanType) {
    const moduleCards = document.querySelectorAll('.module-card');
    
    switch (scanType) {
        case 'full':
            // Select all modules
            moduleCards.forEach(card => {
                card.classList.add('selected');
                const checkbox = card.querySelector('input[type="checkbox"]');
                if (checkbox) {
                    checkbox.checked = true;
                }
            });
            break;
            
        case 'quick':
            // Select only high-impact modules
            moduleCards.forEach(card => {
                const moduleType = card.getAttribute('data-module-type');
                const isHighImpact = ['xss_scanner', 'sql_injection', 'ssrf_scanner', 'rfi_scanner'].includes(moduleType);
                
                if (isHighImpact) {
                    card.classList.add('selected');
                    const checkbox = card.querySelector('input[type="checkbox"]');
                    if (checkbox) {
                        checkbox.checked = true;
                    }
                } else {
                    card.classList.remove('selected');
                    const checkbox = card.querySelector('input[type="checkbox"]');
                    if (checkbox) {
                        checkbox.checked = false;
                    }
                }
            });
            break;
            
        case 'passive':
            // Select only passive modules
            moduleCards.forEach(card => {
                const isPassive = card.getAttribute('data-passive') === 'true';
                
                if (isPassive) {
                    card.classList.add('selected');
                    const checkbox = card.querySelector('input[type="checkbox"]');
                    if (checkbox) {
                        checkbox.checked = true;
                    }
                } else {
                    card.classList.remove('selected');
                    const checkbox = card.querySelector('input[type="checkbox"]');
                    if (checkbox) {
                        checkbox.checked = false;
                    }
                }
            });
            break;
            
        case 'custom':
            // Clear all selections
            moduleCards.forEach(card => {
                card.classList.remove('selected');
                const checkbox = card.querySelector('input[type="checkbox"]');
                if (checkbox) {
                    checkbox.checked = false;
                }
            });
            break;
    }
}

// Update active scans UI
function updateActiveScansUI() {
    const activeScansContainer = document.getElementById('active-scans');
    if (!activeScansContainer) return;
    
    // Clear container
    activeScansContainer.innerHTML = '';
    
    // Check if there are active scans
    if (Object.keys(activeScanData).length === 0) {
        activeScansContainer.innerHTML = '<div class="text-center text-muted py-4">No active scans</div>';
        return;
    }
    
    // Add each active scan
    for (const scanId in activeScanData) {
        const scan = activeScanData[scanId];
        
        const scanCard = document.createElement('div');
        scanCard.className = 'card mb-3';
        scanCard.id = `scan-card-${scanId}`;
        
        // Create status badge class
        let statusBadgeClass = 'badge-queued';
        if (scan.status === 'running') statusBadgeClass = 'badge-running';
        if (scan.status === 'completed') statusBadgeClass = 'badge-completed';
        if (scan.status === 'failed') statusBadgeClass = 'badge-failed';
        
        scanCard.innerHTML = `
            <div class="card-header d-flex justify-content-between align-items-center">
                <div>
                    <span class="badge ${statusBadgeClass} me-2">${scan.status}</span>
                    <strong>${scan.target}</strong>
                </div>
                <div>
                    <button class="btn btn-sm btn-outline-primary view-scan-btn" data-scan-id="${scanId}">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn btn-sm btn-outline-danger stop-scan-btn" data-scan-id="${scanId}">
                        <i class="fas fa-stop"></i> Stop
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="d-flex justify-content-between mb-2">
                    <div>Scan ID: <code>${scanId}</code></div>
                    <div>Type: ${scan.type}</div>
                </div>
                <div class="mb-2">
                    <div class="d-flex justify-content-between">
                        <span>Progress:</span>
                        <span>${scan.progress || 0}%</span>
                    </div>
                    <div class="progress">
                        <div class="progress-bar" role="progressbar" style="width: ${scan.progress || 0}%" 
                            aria-valuenow="${scan.progress || 0}" aria-valuemin="0" aria-valuemax="100"></div>
                    </div>
                </div>
                <div class="d-flex justify-content-between">
                    <div>Started: ${new Date(scan.start_time).toLocaleString()}</div>
                    <div>Vulnerabilities: <span class="text-danger fw-bold">${scan.vulnerabilities ? scan.vulnerabilities.length : 0}</span></div>
                </div>
            </div>
        `;
        
        activeScansContainer.appendChild(scanCard);
    }
}

// Update recent vulnerabilities UI
function updateRecentVulnerabilitiesUI() {
    const vulnContainer = document.getElementById('recent-vulnerabilities');
    if (!vulnContainer) return;
    
    // Clear container
    vulnContainer.innerHTML = '';
    
    // Check if there are vulnerabilities
    if (recentVulnerabilities.length === 0) {
        vulnContainer.innerHTML = '<div class="text-center text-muted py-4">No vulnerabilities found</div>';
        return;
    }
    
    // Create table
    const table = document.createElement('table');
    table.className = 'table table-hover vuln-table';
    
    // Create table header
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>URL</th>
            <th>Scan</th>
            <th>Time</th>
        </tr>
    `;
    table.appendChild(thead);
    
    // Create table body
    const tbody = document.createElement('tbody');
    
    recentVulnerabilities.forEach(vuln => {
        const tr = document.createElement('tr');
        
        // Determine severity class
        let severityClass = '';
        if (vuln.severity === 'High') severityClass = 'severity-high';
        if (vuln.severity === 'Medium') severityClass = 'severity-medium';
        if (vuln.severity === 'Low') severityClass = 'severity-low';
        
        tr.innerHTML = `
            <td><span class="${severityClass}">${vuln.severity}</span></td>
            <td>${vuln.type}</td>
            <td><a href="${vuln.url}" target="_blank" title="${vuln.url}">${truncateUrl(vuln.url, 30)}</a></td>
            <td><a href="/scan/${vuln.scan_id}">${vuln.scan_id.substring(0, 8)}...</a></td>
            <td>${new Date(vuln.timestamp).toLocaleString()}</td>
        `;
        
        tbody.appendChild(tr);
    });
    
    table.appendChild(tbody);
    vulnContainer.appendChild(table);
}

// Update recent scans UI
function updateRecentScansUI() {
    const recentScansContainer = document.getElementById('recent-scans');
    if (!recentScansContainer) return;
    
    // Clear container
    recentScansContainer.innerHTML = '';
    
    // Check if there are recent scans
    if (recentScans.length === 0) {
        recentScansContainer.innerHTML = '<div class="text-center text-muted py-4">No recent scans</div>';
        return;
    }
    
    // Create table
    const table = document.createElement('table');
    table.className = 'table table-hover';
    
    // Create table header
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th>Target</th>
            <th>Type</th>
            <th>Status</th>
            <th>Vulnerabilities</th>
            <th>Time</th>
            <th>Actions</th>
        </tr>
    `;
    table.appendChild(thead);
    
    // Create table body
    const tbody = document.createElement('tbody');
    
    recentScans.forEach(scan => {
        const tr = document.createElement('tr');
        
        // Create status badge class
        let statusBadgeClass = 'badge-queued';
        if (scan.status === 'running') statusBadgeClass = 'badge-running';
        if (scan.status === 'completed') statusBadgeClass = 'badge-completed';
        if (scan.status === 'failed') statusBadgeClass = 'badge-failed';
        
        tr.innerHTML = `
            <td><a href="${scan.target}" target="_blank" title="${scan.target}">${truncateUrl(scan.target, 30)}</a></td>
            <td>${scan.type}</td>
            <td><span class="badge ${statusBadgeClass}">${scan.status}</span></td>
            <td><span class="text-danger fw-bold">${scan.vulnerabilities ? scan.vulnerabilities.length : 0}</span></td>
            <td>${new Date(scan.start_time).toLocaleString()}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary view-scan-btn" data-scan-id="${scan.id}">
                    <i class="fas fa-eye"></i> View
                </button>
            </td>
        `;
        
        tbody.appendChild(tr);
    });
    
    table.appendChild(tbody);
    recentScansContainer.appendChild(table);
}

// Update statistics
function updateStatistics() {
    // Count active scans
    const activeScansCount = Object.keys(activeScanData).length;
    updateStatValue('active-scans-count', activeScansCount);
    
    // Count total vulnerabilities
    let totalVulnerabilities = recentVulnerabilities.length;
    for (const scanId in activeScanData) {
        if (activeScanData[scanId].vulnerabilities) {
            totalVulnerabilities += activeScanData[scanId].vulnerabilities.length;
        }
    }
    updateStatValue('total-vulnerabilities-count', totalVulnerabilities);
    
    // Count total scans
    const totalScans = recentScans.length + activeScansCount;
    updateStatValue('total-scans-count', totalScans);
}

// Helper function to update stat value with animation
function updateStatValue(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue !== value) {
            element.textContent = value;
            element.classList.add('loading');
            setTimeout(() => {
                element.classList.remove('loading');
            }, 1000);
        }
    }
}

// Helper function to truncate URL
function truncateUrl(url, maxLength) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
}

// Show toast notification
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        // Create toast container if it doesn't exist
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '5';
        document.body.appendChild(container);
    }
    
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.id = toastId;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    document.getElementById('toast-container').appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 5000
    });
    bsToast.show();
    
    // Remove toast from DOM after it's hidden
    toast.addEventListener('hidden.bs.toast', function () {
        toast.remove();
    });
}