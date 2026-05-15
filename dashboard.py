#!/usr/bin/env python3
"""
Web Dashboard for HoneyPot
Flask-based interface to view attacks and statistics
"""

from flask import Flask, send_file, request, jsonify
from flask_cors import CORS
from database import Database
from config import Config
from pathlib import Path
import json
from datetime import datetime, timedelta


class Dashboard:
    """Web dashboard for HoneyPot"""
    
    def __init__(self, config_file='config.json', port=5000):
        """Initialize dashboard"""
        self.config = Config(config_file)
        self.db = Database(self.config.db_path)
        self.port = port
        
        self.app = Flask(__name__)
        CORS(self.app)
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        @self.app.route('/dashboard')
        def index():
            """Serve the dashboard UI"""
            dashboard_path = Path(__file__).resolve().parent / 'dashboard.html'
            if dashboard_path.exists():
                return send_file(dashboard_path)
            return jsonify({'error': 'Dashboard UI not found'}), 404
        
        @self.app.route('/api/sessions')
        def get_sessions():
            """Get sessions list"""
            page = request.args.get('page', 1, type=int)
            limit = 50
            offset = (page - 1) * limit
            
            sessions = self.db.get_sessions(limit=limit, offset=offset)
            
            # Convert datetime objects to strings
            for session in sessions:
                if isinstance(session['start_time'], str):
                    continue
                session['start_time'] = str(session['start_time'])
                if session['end_time']:
                    session['end_time'] = str(session['end_time'])
            
            return jsonify({
                'sessions': sessions,
                'page': page
            })
        
        @self.app.route('/api/sessions/<int:session_id>')
        def get_session_detail(session_id):
            """Get session details"""
            try:
                session = self.db.get_session_details(session_id)
                
                # Convert datetime objects
                session['start_time'] = str(session['start_time'])
                if session['end_time']:
                    session['end_time'] = str(session['end_time'])
                
                return jsonify(session)
            except Exception as e:
                return jsonify({'error': str(e)}), 404
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """Get alerts"""
            page = request.args.get('page', 1, type=int)
            limit = 50
            offset = (page - 1) * limit
            
            alerts = self.db.get_alerts(limit=limit, offset=offset)
            
            # Convert datetime objects
            for alert in alerts:
                if isinstance(alert['timestamp'], str):
                    continue
                alert['timestamp'] = str(alert['timestamp'])
            
            return jsonify({
                'alerts': alerts,
                'page': page
            })
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get base statistics"""
            stats = self.db.get_stats()
            
            # Add time-based stats
            sessions = self.db.get_sessions(limit=10000)
            
            hourly_attacks = {}
            for session in sessions:
                if isinstance(session['start_time'], str):
                    dt = datetime.fromisoformat(session['start_time'])
                else:
                    dt = session['start_time']
                hour = dt.strftime('%Y-%m-%d %H:00')
                hourly_attacks[hour] = hourly_attacks.get(hour, 0) + 1
            
            stats['hourly_attacks'] = hourly_attacks
            
            return jsonify(stats)

        @self.app.route('/api/overview')
        def get_overview():
            """Get dashboard overview metrics"""
            stats = self.db.get_stats()
            alert_counts = self.db.get_alert_counts_by_level()
            service_counts = self.db.get_session_counts_by_service()
            
            return jsonify({
                'stats': stats,
                'alert_counts': alert_counts,
                'service_counts': service_counts
            })
        
        @self.app.route('/api/top-ips')
        def get_top_ips():
            """Get top attacking IPs"""
            sessions = self.db.get_sessions(limit=10000)
            
            ip_counts = {}
            for session in sessions:
                ip = session['client_ip']
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            
            return jsonify({
                'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips]
            })
        
        @self.app.route('/api/search')
        def search():
            """Search sessions by IP"""
            query = request.args.get('q', '')
            
            if not query:
                return jsonify({
                    'results': [],
                    'total': 0,
                    'message': 'No search query provided'
                })
            
            sessions = self.db.get_sessions(limit=10000)
            results = [s for s in sessions if query.lower() in s['client_ip'].lower()]
            
            return jsonify({
                'results': results[:50],
                'total': len(results)
            })
        
        @self.app.route('/api/health')
        def health():
            """Health check endpoint"""
            return jsonify({'status': 'ok'})
    
    def run(self):
        """Start the dashboard"""
        print(f"Starting Dashboard on http://localhost:{self.port}")
        self.app.run(host='0.0.0.0', port=self.port, debug=False)


if __name__ == '__main__':
    dashboard = Dashboard()
    dashboard.run()
