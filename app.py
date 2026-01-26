#!/usr/bin/env python3
"""
Flask REST API Backend for Network Intrusion Detection System
Provides endpoints for real-time monitoring and control
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import logging
import os
import json
from threading import Thread

# Import NIDS components
from src.nids_engine import NIDSEngine
from src.logger import setup_logger
from src.config import load_config

app = Flask(__name__)
CORS(app)  # Enable CORS for web dashboard

# Setup logging
logger = setup_logger('api', 'logs/api.log')

# Initialize NIDS engine
config = load_config('config.json')
nids_engine = None
monitoring_thread = None

# In-memory storage for demo (replace with database in production)
alerts_storage = []
stats_storage = {
    'total_packets': 0,
    'normal_count': 0,
    'suspicious_count': 0,
    'malicious_count': 0,
    'active_threats': 0,
    'packets_per_second': 0,
    'status': 'Stopped'
}


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current system statistics"""
    try:
        return jsonify(stats_storage), 200
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify(alerts_storage[-limit:]), 200
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>', methods=['GET'])
def get_alert_details(alert_id):
    """Get specific alert details"""
    try:
        alert = next((a for a in alerts_storage if a['id'] == alert_id), None)
        if alert:
            return jsonify(alert), 200
        return jsonify({'error': 'Alert not found'}), 404
    except Exception as e:
        logger.error(f"Error fetching alert details: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged"""
    try:
        for alert in alerts_storage:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_at'] = datetime.now().isoformat()
                return jsonify(alert), 200
        return jsonify({'error': 'Alert not found'}), 404
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    try:
        resolution = request.json.get('resolution', '')
        for alert in alerts_storage:
            if alert['id'] == alert_id:
                alert['resolved'] = True
                alert['resolved_at'] = datetime.now().isoformat()
                alert['resolution'] = resolution
                return jsonify(alert), 200
        return jsonify({'error': 'Alert not found'}), 404
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current NIDS configuration"""
    try:
        return jsonify(config), 200
    except Exception as e:
        logger.error(f"Error fetching config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def update_config():
    """Update NIDS configuration"""
    try:
        new_config = request.json
        # Validate and update config
        global config
        config.update(new_config)
        
        # Save to file
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info("Configuration updated successfully")
        return jsonify({'message': 'Configuration updated', 'config': config}), 200
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start NIDS monitoring"""
    try:
        global nids_engine, monitoring_thread, stats_storage
        
        if nids_engine and nids_engine.running:
            return jsonify({'message': 'Monitoring already running'}), 200
        
        # Initialize and start NIDS engine
        nids_engine = NIDSEngine(config)
        monitoring_thread = Thread(target=nids_engine.start)
        monitoring_thread.start()
        
        stats_storage['status'] = 'Running'
        logger.info("NIDS monitoring started")
        
        return jsonify({'message': 'Monitoring started', 'status': 'Running'}), 200
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop NIDS monitoring"""
    try:
        global nids_engine, stats_storage
        
        if nids_engine:
            nids_engine.stop()
            stats_storage['status'] = 'Stopped'
            logger.info("NIDS monitoring stopped")
            return jsonify({'message': 'Monitoring stopped', 'status': 'Stopped'}), 200
        
        return jsonify({'message': 'Monitoring not running'}), 200
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
