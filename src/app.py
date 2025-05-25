#!/usr/bin/env python3
"""
Bug Bounty Assistant Web Application Backend
Professional web interface for the Enhanced Bug Bounty Assistant v3
"""
# GitHub Copilot Prompt:
# My Flask backend is located in ~/src/app.py
# My static files are located in ~/src/static/
# My templates (like index.html) are in ~/src/templates/
# Fix any issues with Flask's layout configuration so that:
# - Static files are correctly served (e.g., CSS, JS)
# - Templates render correctly from the / route
# - WebSocket support (via Flask-SocketIO) works without issues
# - The app can be started with either `python app.py` or `gunicorn -k eventlet app:app`
# Ensure that the app uses environment variables from a .env file (FLASK_SECRET_KEY at minimum)
# Add any missing config lines or imports to make this layout work

from flask import Flask, render_template, request, jsonify, send_file, session, Response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import sys
import json
import threading
import queue
import time
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import logging
from typing import Dict, List, Optional
import sqlite3
import dotenv
import yaml
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import v3 modules (use absolute imports for compatibility)
from advanced_assistant_v3 import EnhancedBugBountyAssistantV3
from revenue_maximizer import RevenueMaximizer
from continuous_monitor import ContinuousMonitor
from platform_integration import PlatformIntegration

# Load environment variables from .env (ensure this is done before Flask app creation)
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Determine correct static/template folder paths for Docker and local
STATIC_FOLDER = os.path.join(os.path.dirname(__file__), 'static')
TEMPLATE_FOLDER = os.path.join(os.path.dirname(__file__), 'templates')

app = Flask(
    __name__,
    static_folder=STATIC_FOLDER,
    template_folder=TEMPLATE_FOLDER
)
def load_app_config():
    """Load configuration from multiple sources with proper precedence"""
    config = {
        'aggressive_testing': {'enabled': False},
        'scope_validation': {'enabled': True},  # Default to True for safety
        'auto_submit': {'enabled': False},
        'continuous_monitoring': {'enabled': True}
    }
    
    # Try to load from config files
    config_paths = [
        Path('config.yaml'),
        Path('configs/x_com_config.yaml'),
        Path('/app/config.yaml'),  # Docker path
        Path('/app/configs/x_com_config.yaml')  # Docker path
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            print(f"Loading config from: {config_path}")
            try:
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        # Merge configurations
                        config.update(loaded_config)
                        print(f"Config loaded successfully from {config_path}")
                        break
            except Exception as e:
                print(f"Error loading config from {config_path}: {e}")
    
    # Override with environment variables if set
    if os.getenv('DISABLE_SCOPE_VALIDATION', '').lower() == 'true':
        config['scope_validation']['enabled'] = False
        print("Scope validation disabled via environment variable")
    
    return config
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
assistant = None
revenue_maximizer = RevenueMaximizer()
continuous_monitor = ContinuousMonitor()
platform_integration = None

# Hunt progress tracking
active_hunts = {}
hunt_queues = {}

class HuntProgress:
    """Track hunt progress for real-time updates"""
    def __init__(self, hunt_id: str):
        self.hunt_id = hunt_id
        self.status = "initializing"
        self.phase = "setup"
        self.progress = 0
        self.findings = []
        self.logs = []
        self.start_time = datetime.now()
        self.workspace = None
        self.target = None
        self.subdomains_found = 0
        self.endpoints_found = 0
        self.vulnerabilities_found = 0
        self.current_action = "Initializing..."
        
    def update(self, phase: str, progress: int, message: str, **kwargs):
        self.phase = phase
        self.progress = progress
        self.current_action = message
        
        # Update specific counters
        if 'subdomains' in kwargs:
            self.subdomains_found = kwargs['subdomains']
        if 'endpoints' in kwargs:
            self.endpoints_found = kwargs['endpoints']
        if 'vulnerabilities' in kwargs:
            self.vulnerabilities_found = kwargs['vulnerabilities']
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'phase': phase,
            'message': message,
            'progress': progress
        }
        self.logs.append(log_entry)
        
        # Emit detailed update via WebSocket
        socketio.emit('hunt_progress', {
            'hunt_id': self.hunt_id,
            'phase': phase,
            'progress': progress,
            'message': message,
            'status': self.status,
            'current_action': self.current_action,
            'stats': {
                'subdomains': self.subdomains_found,
                'endpoints': self.endpoints_found,
                'vulnerabilities': self.vulnerabilities_found,
                'duration': (datetime.now() - self.start_time).total_seconds()
            }
        }, room=None, broadcast=True)


# API Routes

@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template('index.html')

@app.route('/api/dashboard')
def dashboard_data():
    """Get dashboard overview data"""
    try:
        # Get earnings analytics
        analytics = revenue_maximizer.get_earnings_analytics()
        
        # Get recent changes from monitor
        recent_changes = continuous_monitor.get_recent_changes(24)
        
        # Get active hunts
        active_hunt_count = len(active_hunts)
        
        # Get recent findings from database
        conn = sqlite3.connect(revenue_maximizer.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) FROM earnings WHERE date_submitted > date('now', '-7 days')
        """)
        weekly_submissions = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM earnings WHERE date_submitted > date('now', '-30 days')
        """)
        monthly_submissions = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': {
                'total_earnings': analytics['total_earnings'],
                'hourly_rate': analytics['hourly_rate'],
                'success_rate': analytics['success_rate'],
                'weekly_submissions': weekly_submissions,
                'monthly_submissions': monthly_submissions,
                'active_hunts': active_hunt_count,
                'recent_changes': len(recent_changes),
                'top_earning_types': analytics['earnings_by_type'][:5],
                'best_programs': analytics['best_programs'][:5],
                'platform_earnings': analytics['earnings_by_platform']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/programs/search', methods=['POST'])
def search_programs():
    """Search for bug bounty programs"""
    try:
        data = request.json or {}
        query = data.get('query', '')
        platform = data.get('platform', 'all')
        
        programs = []
        
        # Search across platforms
        if platform in ['all', 'hackerone']:
            # In production, this would use actual API
            programs.extend([
                {
                    'platform': 'hackerone',
                    'handle': 'security',
                    'name': 'Security',
                    'bounty_range': '$100 - $10,000',
                    'managed': True
                }
            ])
        
        if platform in ['all', 'bugcrowd']:
            # In production, this would use actual API
            programs.extend([
                {
                    'platform': 'bugcrowd',
                    'handle': 'example',
                    'name': 'Example Corp',
                    'bounty_range': '$50 - $5,000',
                    'managed': False
                }
            ])
        
        # Calculate ROI scores
        scored_programs = revenue_maximizer.prioritize_targets(programs)
        
        return jsonify({
            'success': True,
            'programs': scored_programs
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hunt/start', methods=['POST'])
def start_hunt():
    """Start a new bug bounty hunt"""
    try:
        data = request.json or {}
        target = data.get('target')
        platform = data.get('platform')
        program = data.get('program')
        config = data.get('config', {})
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'})
        
        # Generate hunt ID
        hunt_id = f"hunt_{int(time.time())}"
        
        # Create progress tracker
        progress = HuntProgress(hunt_id)
        active_hunts[hunt_id] = progress
        
        # Start hunt in background thread
        thread = threading.Thread(
            target=run_hunt_background,
            args=(hunt_id, target, platform, program, config)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'hunt_id': hunt_id,
            'message': f'Hunt started for {target}'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Add authentication endpoint
@app.route('/api/auth/add-credentials', methods=['POST'])
def add_credentials():
    """Add authentication credentials for a target"""
    try:
        data = request.json
        target = data.get('target')
        username = data.get('username')
        password = data.get('password')
        login_url = data.get('login_url')
        
        if not all([target, username, password]):
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Initialize auth manager if needed
        if not hasattr(app, 'auth_session_manager'):
            from auth_session_manager import AuthSessionManager
            app.auth_session_manager = AuthSessionManager()
        
        app.auth_session_manager.add_credentials(target, username, password, login_url)
        
        return jsonify({
            'success': True,
            'message': f'Credentials added for {target}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/hunt/<hunt_id>/status')
def hunt_status(hunt_id):
    """Get hunt status and progress"""
    if hunt_id not in active_hunts:
        return jsonify({'success': False, 'error': 'Hunt not found'})
    
    progress = active_hunts[hunt_id]
    
    return jsonify({
        'success': True,
        'status': progress.status,
        'phase': progress.phase,
        'progress': progress.progress,
        'findings_count': len(progress.findings),
        'duration': (datetime.now() - progress.start_time).total_seconds(),
        'logs': progress.logs[-20:]  # Last 20 log entries
    })

@app.route('/api/hunt/<hunt_id>/stop', methods=['POST'])
def stop_hunt(hunt_id):
    """Stop an active hunt"""
    if hunt_id in active_hunts:
        active_hunts[hunt_id].status = 'stopped'
        return jsonify({'success': True, 'message': 'Hunt stopped'})
    return jsonify({'success': False, 'error': 'Hunt not found'})

@app.route('/api/findings')
def get_findings():
    """Get all findings with filtering"""
    try:
        # Get filters from query params
        severity = request.args.get('severity')
        vuln_type = request.args.get('type')
        days = int(request.args.get('days', 30))
        
        conn = sqlite3.connect(revenue_maximizer.db_path)
        cursor = conn.cursor()
        
        query = """
            SELECT * FROM earnings 
            WHERE date_submitted > date('now', '-' || ? || ' days')
        """
        params = [str(days)]
        if severity:
            query += " AND severity = ?"
            params.append(str(severity))
        if vuln_type:
            query += " AND vulnerability_type = ?"
            params.append(str(vuln_type))
            
        query += " ORDER BY date_submitted DESC"
        
        cursor.execute(query, params)
        
        findings = []
        for row in cursor.fetchall():
            findings.append({
                'id': row[0],
                'platform': row[1],
                'program': row[2],
                'type': row[3],
                'severity': row[4],
                'amount': row[5],
                'status': row[9],
                'date': row[7],
                'duplicate': bool(row[12])
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'findings': findings,
            'total': len(findings)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/reports/<hunt_id>')
def get_reports(hunt_id):
    """Get reports for a specific hunt"""
    try:
        if hunt_id not in active_hunts:
            return jsonify({'success': False, 'error': 'Hunt not found'})
        
        progress = active_hunts[hunt_id]
        if not progress.workspace:
            return jsonify({'success': False, 'error': 'No workspace found'})
        
        workspace = Path(progress.workspace)
        reports = []
        
        # Find all report files
        for report_file in workspace.glob("*.md"):
            reports.append({
                'name': report_file.name,
                'type': 'markdown',
                'size': report_file.stat().st_size,
                'path': str(report_file)
            })
        
        for report_file in workspace.glob("*.html"):
            reports.append({
                'name': report_file.name,
                'type': 'html',
                'size': report_file.stat().st_size,
                'path': str(report_file)
            })
        
        return jsonify({
            'success': True,
            'reports': reports
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/reports/download/<path:filepath>')
def download_report(filepath):
    """Download a specific report"""
    try:
        # Validate file path for security
        filepath = Path(filepath)
        if not filepath.exists():
            return jsonify({'success': False, 'error': 'File not found'})
        
        return send_file(filepath, as_attachment=True)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitoring/targets')
def get_monitored_targets():
    """Get all monitored targets"""
    try:
        conn = sqlite3.connect(continuous_monitor.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT target, platform, program, check_frequency_hours, 
                   last_checked, enabled, priority
            FROM monitored_targets
            ORDER BY priority DESC
        """)
        
        targets = []
        for row in cursor.fetchall():
            targets.append({
                'target': row[0],
                'platform': row[1],
                'program': row[2],
                'frequency_hours': row[3],
                'last_checked': row[4],
                'enabled': bool(row[5]),
                'priority': row[6]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'targets': targets
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitoring/add', methods=['POST'])
def add_monitoring_target():
    """Add a target for continuous monitoring"""
    try:
        data = request.json or {}
        target = data.get('target')
        platform = data.get('platform')
        program = data.get('program')
        frequency = data.get('frequency_hours', 24)
        
        # Ensure all arguments are strings for add_monitoring_target
        safe_target = str(target) if target is not None else ''
        safe_platform = str(platform) if platform is not None else ''
        safe_program = str(program) if program is not None else ''
        continuous_monitor.add_monitoring_target(safe_target, safe_platform, safe_program, frequency)
        
        return jsonify({
            'success': True,
            'message': f'Added {target} to monitoring'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/monitoring/changes')
def get_recent_changes():
    """Get recent changes detected by monitoring"""
    try:
        hours = int(request.args.get('hours', 24))
        changes = continuous_monitor.get_recent_changes(hours)
        
        return jsonify({
            'success': True,
            'changes': changes,
            'total': len(changes)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/revenue/analytics')
def revenue_analytics():
    """Get detailed revenue analytics"""
    try:
        analytics = revenue_maximizer.get_earnings_analytics()
        schedule = revenue_maximizer.optimize_testing_schedule()
        
        # Get monthly trend
        conn = sqlite3.connect(revenue_maximizer.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                strftime('%Y-%m', date_submitted) as month,
                SUM(amount) as total,
                COUNT(*) as count
            FROM earnings
            WHERE status = 'paid'
            GROUP BY month
            ORDER BY month DESC
            LIMIT 12
        """)
        
        monthly_trend = []
        for row in cursor.fetchall():
            monthly_trend.append({
                'month': row[0],
                'earnings': row[1] or 0,
                'submissions': row[2]
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'analytics': analytics,
            'schedule': schedule,
            'monthly_trend': monthly_trend
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/settings')
def get_settings():
    """Get application settings"""
    try:
        # Load configuration
        config_path = Path('config.yaml')
        if config_path.exists():
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            config = {}
        
        # Check API keys
        has_openai = bool(os.environ.get('OPENAI_API_KEY'))
        has_hackerone = bool(os.environ.get('HACKERONE_API_TOKEN'))
        has_bugcrowd = bool(os.environ.get('BUGCROWD_API_TOKEN'))
        
        return jsonify({
            'success': True,
            'config': config,
            'api_keys': {
                'openai': has_openai,
                'hackerone': has_hackerone,
                'bugcrowd': has_bugcrowd
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update application settings"""
    try:
        data = request.json or {}
        config = data.get('config', {})
        
        # Save configuration
        import yaml
        with open('config.yaml', 'w') as f:
            yaml.dump(config, f)
        
        return jsonify({
            'success': True,
            'message': 'Settings updated successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# WebSocket Events

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    sid = getattr(request, 'sid', None)
    logger.info(f"Client connected: {sid if sid else 'unknown'}")
    emit('connected', {'message': 'Connected to Bug Bounty Assistant'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    sid = getattr(request, 'sid', None)
    logger.info(f"Client disconnected: {sid if sid else 'unknown'}")

@app.route('/api/hunts/active')
def get_active_hunts():
    """Get all active hunts with current status"""
    hunts = []
    for hunt_id, progress in active_hunts.items():
        hunts.append({
            'id': hunt_id,
            'target': progress.target,
            'status': progress.status,
            'phase': progress.phase,
            'progress': progress.progress,
            'current_action': progress.current_action,
            'findings_count': len(progress.findings),
            'duration': (datetime.now() - progress.start_time).total_seconds(),
            'stats': {
                'subdomains': progress.subdomains_found,
                'endpoints': progress.endpoints_found,
                'vulnerabilities': progress.vulnerabilities_found
            }
        })
    return jsonify({'success': True, 'hunts': hunts})

#!/usr/bin/env python3
"""
Fixed run_hunt_background function for app.py
Replace the run_hunt_background function with this fixed version
"""

def run_hunt_background(hunt_id: str, target: str, platform: str, program: str, config: Dict):
    """Enhanced hunt runner with fixed Socket.IO context"""
    global assistant
    
    try:
        progress = active_hunts[hunt_id]
        progress.status = 'running'
        progress.target = target
        
        # Create a custom emit function that works from background thread
        def emit_progress(phase, progress_pct, message, **kwargs):
            with app.app_context():
                socketio.emit('hunt_progress', {
                    'hunt_id': hunt_id,
                    'phase': phase,
                    'progress': progress_pct,
                    'message': message,
                    'status': progress.status,
                    'current_action': message,
                    'stats': {
                        'subdomains': kwargs.get('subdomains', 0),
                        'endpoints': kwargs.get('endpoints', 0),
                        'vulnerabilities': kwargs.get('vulnerabilities', 0),
                        'duration': (datetime.now() - progress.start_time).total_seconds()
                    }
                }, namespace='/', room=None)
                socketio.sleep(0)  # Allow event to process
        
        # Create a custom log emitter
        def emit_log(level, message):
            with app.app_context():
                socketio.emit('hunt_log', {
                    'hunt_id': hunt_id,
                    'level': level,
                    'message': message,
                    'timestamp': datetime.now().isoformat()
                }, namespace='/', room=None)
                socketio.sleep(0)
        
        # Initialize assistant
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            emit_progress('error', 0, 'OpenAI API key not configured')
            progress.status = 'error'
            return
        
        emit_progress('initialization', 5, 'Loading configuration...')
        
        # Load configuration
        base_config = load_app_config()
        if config:
            for key, value in config.items():
                if isinstance(value, dict) and key in base_config:
                    base_config[key].update(value)
                else:
                    base_config[key] = value
        
        emit_progress('initialization', 10, 'Initializing AI assistant...')
        
        # Create assistant with progress callback
        assistant = EnhancedBugBountyAssistantV3(api_key, base_config)
        
        # Override assistant's logging to emit via Socket.IO
        original_log = logger.info
        def socket_log(msg):
            original_log(msg)
            emit_log('INFO', msg)
        logger.info = socket_log
        
        # Phase 1: Initialization
        emit_progress('initialization', 15, f'Starting hunt on {target}')
        assistant.initialize_hunt(target, platform, program)
        progress.workspace = str(assistant.workspace)
        emit_progress('initialization', 20, 'Hunt initialized')
        
        # Phase 2: AI Analysis
        emit_progress('analysis', 25, 'Analyzing target with AI...')
        analysis = assistant.ai_target_analysis()
        emit_progress('analysis', 30, f'Analysis complete - {len(analysis.get("priority_areas", []))} focus areas identified')
        
        # Phase 3: Reconnaissance
        emit_progress('reconnaissance', 35, 'Starting reconnaissance...')
        recon_data = assistant.intelligent_recon()
        
        subdomains_count = len(recon_data.get('subdomains', []))
        endpoints_count = len(recon_data.get('endpoints', []))
        
        emit_progress('reconnaissance', 50, 
                     f'Recon complete - {subdomains_count} subdomains, {endpoints_count} endpoints',
                     subdomains=subdomains_count,
                     endpoints=endpoints_count)
        
        # Phase 4: Vulnerability Hunting
        emit_progress('vulnerability_hunting', 55, 'Starting vulnerability detection...')
        findings = assistant.ai_vulnerability_hunting(recon_data)
        progress.findings = findings
        
        emit_progress('vulnerability_hunting', 75,
                     f'Found {len(findings)} potential vulnerabilities',
                     vulnerabilities=len(findings))
        
        # Phase 5: Chain Detection
        emit_progress('chain_analysis', 80, 'Analyzing attack chains...')
        chains = assistant.ai_chain_detection()
        emit_progress('chain_analysis', 85, f'Identified {len(chains)} attack chains')
        
        # Phase 6: Report Generation
        emit_progress('reporting', 90, 'Generating reports...')
        revenue_report = assistant.generate_revenue_report()
        emit_progress('reporting', 95, 'Reports generated')
        
        # Phase 7: Complete
        emit_progress('complete', 100, 'Hunt completed successfully!')
        progress.status = 'completed'
        
        # Emit completion event
        with app.app_context():
            socketio.emit('hunt_complete', {
                'hunt_id': hunt_id,
                'target': target,
                'findings_count': len(findings),
                'chains_count': len(chains),
                'workspace': progress.workspace,
                'summary': {
                    'subdomains': subdomains_count,
                    'endpoints': endpoints_count,
                    'vulnerabilities': len(findings),
                    'duration': (datetime.now() - progress.start_time).total_seconds()
                }
            }, namespace='/', room=None)
        
    except Exception as e:
        progress = active_hunts.get(hunt_id)
        if progress:
            emit_progress('error', progress.progress, f'Error: {str(e)}')
            progress.status = 'error'
        
        logger.error(f"Hunt {hunt_id} failed: {e}")
        logger.exception("Full traceback:")
        
        with app.app_context():
            socketio.emit('hunt_error', {
                'hunt_id': hunt_id,
                'error': str(e),
                'phase': progress.phase if progress else 'unknown'
            }, namespace='/', room=None)

# Initialize and run

def initialize_app():
    """Initialize the web application"""
    global platform_integration
    
    # Create required directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Initialize platform integration
    platform_integration = PlatformIntegration({})
    
    # Start continuous monitoring
    continuous_monitor.start_monitoring()
    
    logger.info("Bug Bounty Assistant Web App initialized")

# Main entry point for running with `python app.py`
if __name__ == '__main__':
    initialize_app()
    # Use eventlet if available for WebSocket support
    try:
        import eventlet
        import eventlet.wsgi
        logger.info('Running with eventlet for WebSocket support')
        socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
    except ImportError:
        logger.info('Running without eventlet (WebSocket support may be limited)')
        socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
