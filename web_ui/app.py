#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PRAWN Web UI Application

This module provides a web interface for the PRAWN security research framework,
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

from core.config_manager import ConfigManager
from core.module_manager import ModuleManager
from core.memory import AgentMemory
from core.ollama_client import OllamaClient
from core.tool_checker import check_all_tools, run_fix
from core.utils import (
    set_manual_proxy,
    get_manual_proxy,
    get_http_log,
    clear_http_log,
    export_har,
    generate_curl_from_entry,
)

from core.engine import PrawnOrchestrator # Import here to avoid circular dependency with tool_checker
from core.schemas import ScanConfig

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('prawn.web_ui')

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app)

@app.context_processor
def inject_flags():
    return {
        'BURP_API_ENABLED': bool(BURP_API_URL)
    }

# AI agent configuration (Ollama)
OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
OLLAMA_API_KEY = os.environ.get('OLLAMA_API_KEY')
OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama3.1')
# Optional Burp REST API base (e.g., http://localhost:8090)
BURP_API_URL = os.environ.get('BURP_API_URL')

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
memory_ctx = AgentMemory()

# Initialize the AI Client
ai_client = OllamaClient(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL)

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/system_health')
def system_health():
    """Render the system health page."""
    return render_template('system_health.html')

@app.route('/scans')
def scans():
    """Render the scans page. Use index template which lists scans via API."""
    return render_template('scans.html')

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
async def start_scan():
    """API endpoint to start a new scan."""
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    # Generate a unique scan ID
    scan_id = f"scan-{int(time.time())}-{target.replace('://', '-').replace('/', '-').replace('.', '-')}"
    
    # Create scan configuration
    scan_config = {
        'target': target,
        'scan_type': scan_type,
        'options': options,
        'output_dir': os.path.join('results', scan_id)
    }

    # Ensure output directory exists
    os.makedirs(scan_config['output_dir'], exist_ok=True)
    
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
    scan_thread = threading.Thread(target=lambda: asyncio.run(run_scan(scan_id, scan_config)))
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
async def api_scans():
    """API endpoint to list active and recent scans."""
    try:
        return jsonify({'success': True, 'active_scans': list(active_scans.values()), 'recent_scans': memory_ctx.get_all_scans()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    """API endpoint to list recent vulnerabilities across all scans."""
    all_vulns = []
    for scan_id, results in memory_ctx.get_all_findings_raw().items(): # Fetch from memory
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

# Manual Mode / Proxy Controls
@app.route('/api/manual_mode', methods=['GET', 'POST'])
def api_manual_mode():
    try:
        if request.method == 'GET':
            state = get_manual_proxy()
            return jsonify({'success': True, 'enabled': state.get('enabled', False), 'addr': state.get('addr')})
        data = request.get_json(force=True) or {}
        enabled = bool(data.get('enabled', False))
        addr = data.get('addr') or os.environ.get('BURP_PROXY', 'http://127.0.0.1:8080')
        set_manual_proxy(enabled, addr)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/http_log')
def api_http_log():
    try:
        limit = int(request.args.get('limit', 200))
        log = get_http_log(limit=limit)
        # attach index for PoC convenience
        out = []
        for i, e in enumerate(log):
            ee = dict(e)
            ee['index'] = i
            out.append(ee)
        return jsonify({'success': True, 'log': out, 'count': len(out)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/http_log/clear', methods=['POST'])
def api_http_log_clear():
    try:
        clear_http_log()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/har')
def api_har():
    try:
        har = export_har()
        return jsonify({'success': True, 'har': har})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/evidence')
def api_evidence():
    """Return the best-matching HTTP log entry and a curl PoC for a given URL."""
    try:
        qurl = request.args.get('url') or (request.json or {}).get('url')
        if not qurl:
            return jsonify({'success': False, 'error': 'Missing url'}), 400
        import urllib.parse as _up
        try:
            q = _up.urlparse(qurl)
            qbase = f"{q.scheme}://{q.netloc}{q.path}"
        except Exception:
            qbase = qurl
        log = get_http_log(limit=1000)
        best = None
        best_score = -1
        for e in log:
            ru = (e.get('request') or {}).get('url') or ''
            score = 0
            if qbase and ru.startswith(qbase):
                score += 10
            if q.netloc and q.netloc in ru:
                score += 5
            if q.path and q.path in ru:
                score += 3
            if score > best_score:
                best = e
                best_score = score
        if not best and log:
            best = log[-1]
        if not best:
            return jsonify({'success': False, 'error': 'No HTTP log entries'}), 404
        curl = generate_curl_from_entry(best)
        return jsonify({'success': True, 'entry': best, 'curl': curl})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/curl')
def api_curl():
    try:
        i = int(request.args.get('i', -1))
        log = get_http_log(limit=500)
        if not log:
            return jsonify({'success': False, 'error': 'No log entries'}), 404
        if i < 0 or i >= len(log):
            i = len(log) - 1
        curl = generate_curl_from_entry(log[i])
        return jsonify({'success': True, 'curl': curl, 'index': i})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy_browser_cmds')
def api_proxy_browser_cmds():
    try:
        state = get_manual_proxy()
        addr = state.get('addr') or 'http://127.0.0.1:8080'
        cmds = {
            'windows': {
                'chrome': f'"%ProgramFiles%/Google/Chrome/Application/chrome.exe" --proxy-server={addr}',
                'firefox': 'Open Options → Network Settings → Manual proxy configuration'
            },
            'macos': {
                'chrome': f'/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome --proxy-server={addr}',
                'firefox': 'Preferences → Network Settings → Manual proxy configuration'
            },
            'linux': {
                'chrome': f'google-chrome --proxy-server={addr}',
                'firefox': 'Preferences → Network Settings → Manual proxy configuration'
            }
        }
        return jsonify({'success': True, 'proxy': addr, 'commands': cmds})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai_command', methods=['POST'])
def ai_command():
    """Execute simple natural language commands for operational control.
    Supported intents:
      - enable/disable manual mode; set proxy address
      - start scan <url> [modules: xss,sql,...]
      - export/download har
      - copy curl (returns curl string)
      - submit to burp <url> (if BURP_API_URL configured)
    """
    try:
        data = request.get_json(force=True) or {}
        cmd_raw = (data.get('command') or data.get('message') or '').strip()
        args = data.get('args') or {}
        if not cmd_raw:
            return jsonify({'success': False, 'error': 'No command provided'}), 400
        cmd = cmd_raw.lower()

        # Manual mode controls
        if 'enable manual' in cmd or 'turn on manual' in cmd or 'manual mode on' in cmd:
            addr = args.get('addr') or os.environ.get('BURP_PROXY', 'http://127.0.0.1:8080')
            set_manual_proxy(True, addr)
            return jsonify({'success': True, 'action': 'manual_mode', 'enabled': True, 'addr': addr})
        if 'disable manual' in cmd or 'turn off manual' in cmd or 'manual mode off' in cmd:
            set_manual_proxy(False, None)
            return jsonify({'success': True, 'action': 'manual_mode', 'enabled': False})
        if cmd.startswith('set proxy') or 'set proxy to' in cmd:
            try:
                import re
                m = re.search(r'(http[s]?://[^\s]+)', cmd_raw)
                addr = m.group(1) if m else (args.get('addr') or 'http://127.0.0.1:8080')
            except Exception:
                addr = args.get('addr') or 'http://127.0.0.1:8080'
            set_manual_proxy(True, addr)
            return jsonify({'success': True, 'action': 'manual_mode', 'enabled': True, 'addr': addr})

        # Exporters
        if 'export har' in cmd or 'download har' in cmd or cmd.strip() == 'har':
            har = export_har()
            return jsonify({'success': True, 'action': 'export_har', 'har': har})
        if 'copy curl' in cmd or cmd.strip() == 'curl':
            log = get_http_log(limit=500)
            if not log:
                return jsonify({'success': False, 'error': 'No HTTP log entries to generate curl'}), 404
            curl = generate_curl_from_entry(log[-1])
            return jsonify({'success': True, 'action': 'copy_curl', 'curl': curl})

        # Start scan: "start scan <url> [modules: xss,sql,...]"
        if cmd.startswith('start scan') or cmd.startswith('scan '):
            try:
                import re
                m = re.search(r'(http[s]?://[^\s]+)', cmd_raw)
                url = m.group(1) if m else (args.get('url'))
            except Exception:
                url = args.get('url')
            if not url:
                return jsonify({'success': False, 'error': 'No target URL found'}), 400
            modules = args.get('modules')
            # Parse modules list if present: modules: xss, sql, csrf
            if 'modules:' in cmd:
                try:
                    after = cmd_raw.split('modules:', 1)[1]
                    modules = [s.strip() for s in after.split(',') if s.strip()]
                except Exception:
                    pass
            scan_type = 'custom' if modules else 'full'
            # Prepare scan config and start thread
            scan_id = f"{int(time.time())}-{url.replace('://', '-').replace('/', '-')}"
            scan_config = {
                'target': url,
                'scan_type': scan_type,
                'options': {'modules': modules} if modules else {},
                'output_dir': os.path.join('results', scan_id)
            }
            active_scans[scan_id] = {
                'id': scan_id,
                'target': url,
                'scan_type': scan_type,
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'starting',
                'progress': 0,
                'modules_completed': 0,
                'total_modules': 0
            }
            t = threading.Thread(target=run_scan, args=(scan_id, scan_config))
            t.daemon = True
            t.start()
            return jsonify({'success': True, 'action': 'start_scan', 'scan_id': scan_id, 'target': url, 'modules': modules or []})

        # Burp submission
        if 'submit to burp' in cmd or 'send to burp' in cmd or cmd.startswith('burp scan'):
            if not BURP_API_URL:
                return jsonify({'success': False, 'error': 'BURP_API_URL not configured'}), 400
            try:
                import re
                m = re.search(r'(http[s]?://[^\s]+)', cmd_raw)
                url = m.group(1) if m else (args.get('url'))
            except Exception:
                url = args.get('url')
            if not url:
                return jsonify({'success': False, 'error': 'No target URL found'}), 400
            resp = requests.post(f"{BURP_API_URL.rstrip('/')}/scan", json={'url': url}, timeout=30)
            ok = resp.status_code < 400
            return jsonify({'success': ok, 'action': 'burp_scan', 'status': resp.status_code, 'resp': resp.text[:500]})

        return jsonify({'success': False, 'error': 'Unrecognized command', 'command': cmd_raw}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system_health')
def api_system_health():
    """API endpoint to get the tool check report."""
    try:
        report = check_all_tools()
        return jsonify({'success': True, 'report': report})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system_fix', methods=['POST'])
def api_system_fix():
    """API endpoint to trigger the automated tool setup."""
    try:
        success = run_fix()
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Optional Burp API wrappers
@app.route('/api/burp/scan', methods=['POST'])
def api_burp_scan():
    try:
        if not BURP_API_URL:
            return jsonify({'success': False, 'error': 'BURP_API_URL not configured'}), 400
        data = request.get_json(force=True) or {}
        url = data.get('url')
        if not url:
            return jsonify({'success': False, 'error': 'Missing url'}), 400
        resp = requests.post(f"{BURP_API_URL.rstrip('/')}/scan", json={'url': url}, timeout=30)
        return jsonify({'success': resp.status_code < 400, 'status': resp.status_code, 'resp': resp.text[:500]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/burp/issues')
def api_burp_issues():
    try:
        if not BURP_API_URL:
            return jsonify({'success': False, 'error': 'BURP_API_URL not configured'}), 400
        resp = requests.get(f"{BURP_API_URL.rstrip('/')}/issues", timeout=30)
        ok = resp.status_code < 400
        jr = resp.json() if ok else {'error': resp.text[:500]}
        return jsonify({'success': ok, 'issues': jr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
        
        if not prompt:
            return jsonify({'success': False, 'error': 'No message provided'}), 400

        # Use the centralized OllamaClient for conversation
        context_history = "\n".join([f"{h['role']}: {h['content']}" for h in history])
        full_prompt = f"{context_history}\nuser: {prompt}"
        
        import asyncio
        reply = asyncio.run(ai_client.generate_text(full_prompt))
        
        return jsonify({'success': True, 'reply': reply, 'model': OLLAMA_MODEL})
        
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
    """Run a scan with the given configuration (async wrapper)."""
    global engine
    global scan_logs
    
    try:
        scan_logs[scan_id] = []
        # Update scan status
        active_scans[scan_id]['status'] = 'running'
        socketio.emit('scan_update', {'scan_id': scan_id, 'status': 'running'})
        
        # Build the Pydantic ScanConfig
        scan_cfg = ScanConfig(
            target=config.get('target'),
            output_dir=config.get('output_dir'),
            zero_day_mode=config.get('options', {}).get('zero_day_mode', False),
            web3_enabled=config.get('options', {}).get('web3_enabled', False),
            economic_threat_model=config.get('options', {}).get('economic_threat_model', False),
            ollama_model=OLLAMA_MODEL,
            max_recursion_depth=config.get('options', {}).get('max_recursion_depth', 2)
        )

        # Record scan start in persistent memory
        try:
            memory_ctx.start_scan(config.get('target'), scan_id, config)
        except Exception:
            pass
        
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
                scan_results[scan_id] = {'findings': []} # Use 'findings' to match AgentOutput
            scan_results[scan_id]['findings'].append(vulnerability)
            # Append to scan log
            try:
                sev = vulnerability.get('severity', 'Info') if isinstance(vulnerability, dict) else 'Info'
                vtype = vulnerability.get('type', 'Vulnerability') if isinstance(vulnerability, dict) else 'Vulnerability'
                scan_logs.setdefault(scan_id, []).append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - [Finding/{sev}] {vtype}")
            except Exception:
                pass
            # Persist finding to memory
            try:
                memory_ctx.record_findings_bulk(active_scans[scan_id]['target'], scan_id, [vulnerability] if isinstance(vulnerability, dict) else [])
            except Exception:
                pass
            socketio.emit('vulnerability_found', {
                'scan_id': scan_id,
                'vulnerability': vulnerability
            })
        
        orchestrator = PrawnOrchestrator(scan_cfg)
        orchestrator._callbacks['progress'] = lambda p: progress_callback("MAS Loop", p, "Agent Thinking...")
        orchestrator._callbacks['vulnerability'] = vulnerability_callback

        # Run the multi-agent research loop
        import asyncio
        result = asyncio.run(orchestrator.execute_research())

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
        # Persist scan end in memory
        try:
            memory_ctx.end_scan(active_scans[scan_id]['target'], scan_id, status='completed')
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
        # Persist error end state
        try:
            memory_ctx.end_scan(active_scans.get(scan_id, {}).get('target'), scan_id, status='error')
        except Exception:
            pass
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)})

def main():
    """Main function to run the web UI."""
    # Create results directory if it doesn't exist
    os.makedirs('results', exist_ok=True)
    
    # Run the Flask application
    host = os.environ.get('PRAWN_HOST', '127.0.0.1') # Changed to 127.0.0.1 for better default security
    port = int(os.environ.get('PRAWN_PORT', 5000)) 
    debug = os.environ.get('PRAWN_DEBUG', 'False').lower() == 'true' # Use 'False' as default for production
    
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True) # allow_unsafe_werkzeug for debug=True

if __name__ == '__main__':
    main()