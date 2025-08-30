#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PIN0CCHI0 Web UI Application

This module provides a web interface for the PIN0CCHI0 security testing framework,
similar to XBOW, allowing users to visualize scan progress and results.
"""

import os
import sys
import json
import logging
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit
import requests

# Add the parent directory to the path so we can import the PIN0CCHI0 modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import Engine
from core.config_manager import ConfigManager
from core.module_manager import ModuleManager

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('pin0cchi0.web_ui')

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app)

# AI agent configuration (Ollama)
OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
OLLAMA_API_KEY = os.environ.get('OLLAMA_API_KEY')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.1')

# Jinja filter for formatting datetime-like values
@app.template_filter('format_datetime')
def format_datetime(value, fmt='%Y-%m-%d %H:%M:%S'):
    """Format timestamps or datetime-like strings safely for templates."""
    from datetime import datetime
    if value is None:
        return ''
    try:
        # Handle numeric timestamps
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime(fmt)
        s = str(value)
        # Strip trailing Z for ISO8601
        if s.endswith('Z'):
            s = s[:-1]
        # Try ISO parse
        try:
            dt = datetime.fromisoformat(s)
            return dt.strftime(fmt)
        except Exception:
            pass
        # Fallback: return original string
        return str(value)
    except Exception:
        return str(value)

# Global variables
active_scans = {}
scan_results = {}
scan_logs = {}
engine = None

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/scans')
def scans():
    """Render the scans page. Use index template which lists scans via API."""
    return render_template('index.html')

@app.route('/scan/<scan_id>')
def scan_detail(scan_id):
    """Render the scan detail page for a specific scan."""
    if scan_id in active_scans:
        return render_template('scan_detail.html', scan=active_scans[scan_id])
    return redirect(url_for('scans'))

@app.route('/vulnerabilities')
def vulnerabilities():
    """Render the vulnerabilities page showing all found vulnerabilities with pagination."""
    all_vulns = []
    for scan_id, results in scan_results.items():
        if isinstance(results, dict) and 'vulnerabilities' in results:
            for vuln in results['vulnerabilities']:
                try:
                    item = dict(vuln)
                except Exception:
                    item = vuln
                item['scan_id'] = scan_id
                all_vulns.append(item)
    # Sort newest first if timestamp available
    try:
        all_vulns.sort(key=lambda v: v.get('timestamp', ''), reverse=True)
    except Exception:
        pass
    # Pagination
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
    except Exception:
        page, per_page = 1, 20
    total = len(all_vulns)
    total_pages = (total + per_page - 1) // per_page if per_page > 0 else 1
    if page < 1:
        page = 1
    if total_pages < 1:
        total_pages = 1
    start = (page - 1) * per_page
    end = start + per_page
    page_vulns = all_vulns[start:end]
    return render_template(
        'vulnerabilities.html',
        vulnerabilities=page_vulns,
        total_pages=total_pages,
        current_page=page,
        per_page=per_page,
        total=total
    )

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """API endpoint to start a new scan."""
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    # Generate a unique scan ID
    scan_id = f"{int(time.time())}-{target.replace('://', '-').replace('/', '-')}"
    
    # Create scan configuration
    scan_config = {
        'target': target,
        'scan_type': scan_type,
        'options': options,
        'output_dir': os.path.join('results', scan_id)
    }
    
    # Initialize the scan in active_scans
    active_scans[scan_id] = {
        'id': scan_id,
        'target': target,
        'scan_type': scan_type,
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'starting',
        'progress': 0,
        'modules_completed': 0,
        'total_modules': 0
    }
    
    # Start the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan, args=(scan_id, scan_config))
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({'success': True, 'scan_id': scan_id})

@app.route('/api/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """API endpoint to stop a running scan."""
    if scan_id in active_scans and active_scans[scan_id]['status'] == 'running':
        # Signal the scan to stop
        active_scans[scan_id]['status'] = 'stopping'
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Scan not found or not running'})

@app.route('/api/scan_status/<scan_id>')
def scan_status(scan_id):
    """API endpoint to get the status of a scan."""
    if scan_id in active_scans:
        return jsonify({'success': True, 'scan': active_scans[scan_id]})
    return jsonify({'success': False, 'error': 'Scan not found'})

@app.route('/api/scan_results/<scan_id>')
def get_scan_results(scan_id):
    """API endpoint to get the results of a scan."""
    if scan_id in scan_results:
        return jsonify({'success': True, 'results': scan_results[scan_id]})
    return jsonify({'success': False, 'error': 'Scan results not found'})

@app.route('/api/scans')
def api_scans():
    """API endpoint to list active scans."""
    try:
        return jsonify({'success': True, 'scans': list(active_scans.values())})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint to list recent vulnerabilities across all scans."""
    all_vulns = []
    for scan_id, results in scan_results.items():
        vulns = results.get('vulnerabilities', []) if isinstance(results, dict) else []
        for v in vulns:
            item = dict(v)
            item['scan_id'] = scan_id
            all_vulns.append(item)
    return jsonify({'success': True, 'vulnerabilities': all_vulns})

@app.route('/api/scan_log/<scan_id>')
def api_scan_log(scan_id):
    """API endpoint to get scan log lines."""
    return jsonify({'success': True, 'log': scan_logs.get(scan_id, [])})

@app.route('/api/ai_chat', methods=['GET', 'POST'])
def ai_chat():
    """Proxy chat requests to an Ollama backend (Jarvis-like conversation)."""
    try:
        if request.method == 'GET':
            example = {
                'method': 'POST',
                'url': '/api/ai_chat',
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'message': 'Hello, summarize last scan',
                    'history': [
                        {'role': 'assistant', 'content': 'Hello, how can I help?'}
                    ],
                    'model': OLLAMA_MODEL
                }
            }
            return jsonify({'success': True, 'usage': 'Send POST with JSON {message, history(optional), model(optional)}', 'example': example})
        data = request.get_json(force=True) or {}
        prompt = (data.get('message') or '').strip()
        history = data.get('history') or []  # list of {role:'user'|'assistant', content:'...'}
        model = data.get('model') or OLLAMA_MODEL
        if not prompt:
            return jsonify({'success': False, 'error': 'No message provided'}), 400

        # Build messages array
        messages = []
        try:
            for h in history:
                r = 'assistant' if (h.get('role') or '').lower() == 'assistant' else 'user'
                c = str(h.get('content') or '')
                if c:
                    messages.append({'role': r, 'content': c})
        except Exception:
            pass
        messages.append({'role': 'user', 'content': prompt})

        headers = {'Content-Type': 'application/json'}
        if OLLAMA_API_KEY:
            headers['Authorization'] = f'Bearer {OLLAMA_API_KEY}'
        payload = {
            'model': model,
            'messages': messages,
            'stream': False,
        }
        resp = requests.post(f"{OLLAMA_BASE_URL}/api/chat", headers=headers, json=payload, timeout=60)
        if resp.status_code >= 400:
            return jsonify({'success': False, 'error': f'Ollama error {resp.status_code}: {resp.text[:300]}'})
        jr = resp.json()
        # Try to extract assistant content (Ollama chat format)
        content = ''
        try:
            msg = jr.get('message') or {}
            content = msg.get('content') or ''
        except Exception:
            pass
        if not content:
            # Fallback to /api/generate-like response
            content = jr.get('response') or ''
        return jsonify({'success': True, 'reply': content, 'model': model})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    logger.info('Client disconnected')

def run_scan(scan_id, config):
    """Run a scan with the given configuration."""
    global engine
    global scan_logs
    
    try:
        scan_logs[scan_id] = []
        # Update scan status
        active_scans[scan_id]['status'] = 'running'
        socketio.emit('scan_update', {'scan_id': scan_id, 'status': 'running'})
        
        # Initialize the engine if not already done
        if engine is None:
            config_manager = ConfigManager()
            module_manager = ModuleManager(config_manager)
            engine = Engine(config_manager, module_manager)
        
        # Configure the engine for this scan
        engine.config.update(config)
        
        # Register progress callback
        def progress_callback(module_name, progress, message):
            active_scans[scan_id]['progress'] = progress
            active_scans[scan_id]['current_module'] = module_name
            active_scans[scan_id]['status_message'] = message
            # Append to scan log
            try:
                scan_logs.setdefault(scan_id, []).append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - [{module_name}] {message} ({progress}%)")
            except Exception:
                pass
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': progress,
                'module': module_name,
                'message': message
            })
        
        # Register vulnerability callback
        def vulnerability_callback(vulnerability):
            if scan_id not in scan_results:
                scan_results[scan_id] = {'vulnerabilities': []}
            scan_results[scan_id]['vulnerabilities'].append(vulnerability)
            # Append to scan log
            try:
                sev = vulnerability.get('severity', 'Info') if isinstance(vulnerability, dict) else 'Info'
                vtype = vulnerability.get('type', 'Vulnerability') if isinstance(vulnerability, dict) else 'Vulnerability'
                scan_logs.setdefault(scan_id, []).append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - [Finding/{sev}] {vtype}")
            except Exception:
                pass
            socketio.emit('vulnerability_found', {
                'scan_id': scan_id,
                'vulnerability': vulnerability
            })
        
        # Set callbacks
        engine.set_callback('progress', progress_callback)
        engine.set_callback('vulnerability', vulnerability_callback)
        
        # Run the scan
        active_scans[scan_id]['total_modules'] = len(engine.module_manager.get_modules())
        result = engine.run()
        
        # Update scan results
        scan_results[scan_id] = result
        
        # Update scan status
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        active_scans[scan_id]['progress'] = 100
        # Append completion log
        try:
            scan_logs.setdefault(scan_id, []).append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Scan completed")
        except Exception:
            pass
        
        # Emit completion event
        socketio.emit('scan_complete', {'scan_id': scan_id, 'status': 'completed'})
        
    except Exception as e:
        logger.error(f"Error running scan {scan_id}: {str(e)}")
        active_scans[scan_id]['status'] = 'error'
        active_scans[scan_id]['error'] = str(e)
        try:
            scan_logs.setdefault(scan_id, []).append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Error: {str(e)}")
        except Exception:
            pass
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})

def main():
    """Main function to run the web UI."""
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    # Run the Flask application
    host = os.environ.get('PIN0CCHI0_HOST', '0.0.0.0')
    port = int(os.environ.get('PIN0CCHI0_PORT', 5000))
    debug = os.environ.get('PIN0CCHI0_DEBUG', 'False').lower() == 'true'
    
    socketio.run(app, host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()