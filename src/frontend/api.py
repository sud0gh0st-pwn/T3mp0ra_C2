#!/usr/bin/env python3
"""
Tempora C2 Web Frontend API
This module provides the API endpoints for communicating with the C2 server.
"""

import os
import sys
import logging
import json
from flask import Blueprint, request, jsonify, current_app, render_template
from c2_api_client import C2APIClient

# Setup logging
logger = logging.getLogger("tempora-api")

# C2 Server API connection settings
C2_API_HOST = os.environ.get('C2_API_HOST', '127.0.0.1')
C2_API_PORT = int(os.environ.get('C2_API_PORT', 5000))

# Create Blueprints for different route groups
api_bp = Blueprint('api', __name__, url_prefix='/api')
recon_bp = Blueprint('recon', __name__, url_prefix='/recon')

# Create a single C2APIClient instance for all API requests
c2_client = C2APIClient(server_host=C2_API_HOST, server_port=C2_API_PORT)

# Scan configuration storage
SCAN_CONFIG_FILE = 'scan_config.json'

# API Routes
@api_bp.route('/status')
def status():
    """Get C2 server status"""
    response = c2_client.send_request('status')
    if response is None:
        return jsonify({'error': 'Could not connect to C2 server'}), 500
    return jsonify(response)

@api_bp.route('/clients')
def get_clients():
    """Get all connected clients"""
    response = c2_client.send_request('clients')
    if response is None:
        return jsonify({'error': 'Could not retrieve clients'}), 500
    return jsonify(response)

@api_bp.route('/clients/<client_id>')
def get_client(client_id):
    """Get details for a specific client"""
    response = c2_client.send_request('client_info', {'client_id': client_id})
    if response is None:
        return jsonify({'error': f'Could not retrieve client {client_id}'}), 500
    return jsonify(response)

@api_bp.route('/task', methods=['POST'])
def create_task():
    """Create a new task for a client"""
    data = request.json
    if not data or 'client_id' not in data or 'command' not in data:
        return jsonify({'error': 'Missing required fields: client_id and command'}), 400
    
    response = c2_client.send_request('create_task', data)
    if response is None:
        return jsonify({'error': 'Failed to create task'}), 500
    
    return jsonify({'success': True, 'task': response})

@api_bp.route('/tasks')
def get_tasks():
    """Get all tasks"""
    response = c2_client.send_request('tasks')
    if response is None:
        return jsonify({'error': 'Could not retrieve tasks'}), 500
    return jsonify(response)

@api_bp.route('/generate_payload', methods=['POST'])
def generate_payload():
    """Generate a new client payload"""
    options = request.json
    if not options:
        return jsonify({'error': 'Missing payload generation options'}), 400
    
    response = c2_client.send_request('generate_payload', options)
    if response is None:
        return jsonify({'error': 'Failed to generate payload'}), 500
    
    return jsonify(response)

# Recon Routes
@recon_bp.route('/scan-range')
def scan_range():
    """Render the scan range configuration page"""
    return render_template('scan_range.html')

@api_bp.route('/recon/scan/start', methods=['POST'])
def start_scan():
    """Start a new network scan"""
    try:
        config = request.form.to_dict()
        
        # Convert string values to appropriate types
        if 'ports' in config:
            config['ports'] = [int(p) for p in config['ports'].split(',')]
        
        numeric_fields = ['max_threads', 'rate_limit', 'timeout', 'max_retries', 
                         'max_connections', 'chunk_size', 'batch_size']
        for field in numeric_fields:
            if field in config:
                config[field] = float(config[field]) if '.' in config[field] else int(config[field])
        
        boolean_fields = ['cache_results', 'common_ports_first']
        for field in boolean_fields:
            if field in config:
                config[field] = config[field] == 'on'
        
        # Send scan request to C2 server
        response = c2_client.send_request('start_scan', config)
        if response is None:
            return jsonify({'error': 'Failed to start scan'}), 500
        
        return jsonify({'success': True, 'scan_id': response.get('scan_id')})
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/recon/scan/progress')
def get_scan_progress():
    """Get the progress of the current scan"""
    try:
        response = c2_client.send_request('scan_progress')
        if response is None:
            return jsonify({'error': 'Failed to get scan progress'}), 500
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error getting scan progress: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/recon/scan/config/save', methods=['POST'])
def save_scan_config():
    """Save the current scan configuration"""
    try:
        config = request.json
        with open(SCAN_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error saving scan configuration: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/recon/scan/config/load')
def load_scan_config():
    """Load the saved scan configuration"""
    try:
        if os.path.exists(SCAN_CONFIG_FILE):
            with open(SCAN_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            return jsonify(config)
        return jsonify({})
    except Exception as e:
        logger.error(f"Error loading scan configuration: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/recon/scan/stop', methods=['POST'])
def stop_scan():
    """Stop the current scan"""
    try:
        response = c2_client.send_request('stop_scan')
        if response is None:
            return jsonify({'error': 'Failed to stop scan'}), 500
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        return jsonify({'error': str(e)}), 500 