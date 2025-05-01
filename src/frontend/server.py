#!/usr/bin/env python3
"""
Tempora C2 Web Server
This module provides the web interface for the Tempora C2 framework.
"""

import os
import sys
import json
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import CSRFProtect
from functools import wraps
from api import api_bp, recon_bp

# Setup logging
logger = logging.getLogger("tempora-server")

# Configuration file path
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')

def load_config():
    """Load settings from config file"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
    return {}

def save_config(settings):
    """Save settings to config file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
csrf = CSRFProtect(app)

# Register blueprints
app.register_blueprint(api_bp)
app.register_blueprint(recon_bp)

# Load initial settings
config = load_config()

# Authentication decorator (simple example - would need proper implementation in production)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        # Simple authentication for demo purposes
        # In production, implement proper authentication
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'tempora':  # This is a placeholder!
            session['authenticated'] = True
            session['username'] = username
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing server status and clients"""
    return render_template('dashboard.html')

@app.route('/clients')
@login_required
def clients():
    """Page listing all connected clients"""
    return render_template('clients.html')

@app.route('/clients/<client_id>')
@login_required
def client_detail(client_id):
    """Page showing details for a specific client"""
    return render_template('client_detail.html', client_id=client_id)

@app.route('/tasks')
@login_required
def tasks():
    """Page for managing tasks"""
    return render_template('tasks.html')

@app.route('/generate_payload')
@login_required
def generate_payload():
    """Page for generating new client payloads"""
    return render_template('generate_payload.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Page for managing server settings"""
    if request.method == 'POST':
        # Handle form submission
        try:
            # Get form data
            new_settings = {
                'server_host': request.form.get('server_host', '127.0.0.1'),
                'server_port': int(request.form.get('server_port', 5000)),
                'web_host': request.form.get('web_host', '0.0.0.0'),
                'web_port': int(request.form.get('web_port', 5001)),
                'use_https': request.form.get('use_https', 'false').lower() == 'true',
                'access_key': request.form.get('access_key', ''),
                'encryption_enabled': request.form.get('encryption_enabled', 'true').lower() == 'true',
                'default_encryption_key': request.form.get('default_encryption_key', ''),
                'log_level': request.form.get('log_level', 'INFO'),
                'log_file': request.form.get('log_file', 'tempora.log'),
                'console_logging': request.form.get('console_logging', 'true').lower() == 'true'
            }
            
            # Save settings to config file
            if save_config(new_settings):
                flash('Settings saved successfully', 'success')
                # Update the global config
                globals()['config'].update(new_settings)
            else:
                flash('Error saving settings', 'danger')
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            flash('Error saving settings', 'danger')
    
    # Get current settings from config or environment
    settings = {
        'server_host': config.get('server_host', os.environ.get('C2_API_HOST', '127.0.0.1')),
        'server_port': int(config.get('server_port', os.environ.get('C2_API_PORT', 5000))),
        'web_host': config.get('web_host', os.environ.get('WEB_HOST', '0.0.0.0')),
        'web_port': int(config.get('web_port', os.environ.get('WEB_PORT', 5001))),
        'use_https': config.get('use_https', os.environ.get('USE_HTTPS', 'false').lower() == 'true'),
        'access_key': config.get('access_key', os.environ.get('ACCESS_KEY', '')),
        'encryption_enabled': config.get('encryption_enabled', os.environ.get('ENCRYPTION_ENABLED', 'true').lower() == 'true'),
        'default_encryption_key': config.get('default_encryption_key', os.environ.get('DEFAULT_ENCRYPTION_KEY', '')),
        'log_level': config.get('log_level', os.environ.get('LOG_LEVEL', 'INFO')),
        'log_file': config.get('log_file', os.environ.get('LOG_FILE', 'tempora.log')),
        'console_logging': config.get('console_logging', os.environ.get('CONSOLE_LOGGING', 'true').lower() == 'true')
    }
    
    # Get system information
    system_info = {
        'python_version': sys.version,
        'os_info': f"{os.name} {sys.platform}",
        'cpu_usage': 'N/A',  # Would need psutil or similar to get real values
        'memory_usage': 'N/A',
        'disk_space': 'N/A',
        'uptime': 'N/A'
    }
    
    # Get server status from C2 server
    try:
        from api import c2_client
        status_response = c2_client.send_request('status')
        server_status = status_response.get('status') == 'online' if status_response else False
    except:
        server_status = False
    
    return render_template('settings.html', 
                         settings=settings,
                         system_info=system_info,
                         server_status=server_status)

@app.route('/recon')
@login_required
def recon():
    """Reconnaissance tools dashboard"""
    return render_template('recon.html')

@app.route('/recon/scan-range')
@login_required
def scan_range():
    """Network scanner configuration page"""
    return render_template('scan_range.html')

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return render_template('error.html', error="Internal server error"), 500 