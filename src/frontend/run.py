#!/usr/bin/env python3
"""
Tempora C2 Frontend Runner
Runs the Flask web interface for the Tempora C2 framework
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Ensure we can import from the parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

def setup_logging(log_level=logging.INFO):
    """Configure logging for the frontend application"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler('frontend.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('tempora-frontend')

def main():
    """Run the Tempora C2 frontend web interface"""
    parser = argparse.ArgumentParser(description='Tempora C2 Frontend Runner')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    logger = setup_logging(logging.DEBUG if args.debug else logging.INFO)
    logger.info(f"Starting Tempora C2 Frontend on {args.host}:{args.port}")
    
    # Import and configure Flask app
    from frontend.server import app
    
    # Run the application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug
    )

if __name__ == '__main__':
    main() 
